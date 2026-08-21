import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from urllib.parse import urlencode

import asyncpg
import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pwdlib.exceptions import PwdlibError

from .auth_schemas import (
    AuthSessionResponse,
    LoginRequest,
    OAuthStartResponse,
    Role,
    SignUpRequest,
    TokenDeliveryResponse,
    UserPublic,
)
from .config import Settings, get_settings
from .mailer import DeliveryService
from .store import PostgresNeedexStore, WorkspaceApiKeyRecord, store

password_hash = PasswordHash.recommended()
dummy_password_hash = password_hash.hash("Needex-not-a-real-account-2026!")
bearer_scheme = HTTPBearer(auto_error=False)
API_KEY_PREFIX = "tv_live_"
ApiKeyScope = Literal[
    "taskviews:artifacts:read",
    "taskviews:data:read",
    "taskviews:analytics:read",
]


class DuplicateEmailError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class AccountLockedError(Exception):
    pass


class OAuthConfigurationError(Exception):
    pass


class OAuthExchangeError(Exception):
    pass


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def verify_password(plain_password: str, encoded_password: str) -> bool:
    try:
        return password_hash.verify(plain_password, encoded_password)
    except PwdlibError:
        return False


async def issue_session(
    user: UserPublic, settings: Settings, repository: PostgresNeedexStore
) -> AuthSessionResponse:
    token = secrets.token_urlsafe(48)
    expires_at = datetime.now(UTC) + timedelta(days=settings.taskview_session_days)
    persisted_expiry = await repository.create_session(
        user_id=user.id,
        token_hash=hash_session_token(token),
        expires_at=expires_at,
    )
    if settings.taskview_require_email_verification and not user.email_verified:
        next_path = "/verify-email"
    elif user.onboarding_status == "workspace_setup":
        next_path = "/onboarding/workspace"
    elif user.onboarding_status == "team_invite":
        next_path = "/onboarding/invite"
    else:
        next_path = "/dashboard"
    return AuthSessionResponse(
        user=user,
        session_token=token,
        expires_at=persisted_expiry,
        next_path=next_path,
    )


async def issue_one_time_token(
    *,
    user_id: str,
    purpose: str,
    lifetime_minutes: int,
    settings: Settings,
    repository: PostgresNeedexStore,
    recipient_email: str,
    delivery: DeliveryService,
) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(48)
    expires_at = datetime.now(UTC) + timedelta(minutes=lifetime_minutes)
    token_ciphertext = delivery.encrypt_token(token)
    persisted_expiry = await repository.issue_one_time_token(
        user_id=user_id,
        purpose=purpose,
        token_hash=hash_session_token(token),
        expires_at=expires_at,
        recipient_email=recipient_email,
        token_ciphertext=token_ciphertext,
    )
    return token, persisted_expiry


async def sign_up(
    request: SignUpRequest, settings: Settings, repository: PostgresNeedexStore
) -> AuthSessionResponse:
    requires_verification = settings.taskview_require_email_verification
    delivery = DeliveryService(settings) if requires_verification else None
    if delivery is not None:
        delivery.ensure_api_ready()
    try:
        user = await repository.create_user(
            email=str(request.email).lower(),
            display_name=request.display_name,
            password_hash=password_hash.hash(request.password),
            role="requester",
            email_verified=not requires_verification,
            marketing_opt_in=request.marketing_opt_in,
            onboarding_status=(
                "email_verification" if requires_verification else "workspace_setup"
            ),
        )
    except asyncpg.UniqueViolationError as exc:
        raise DuplicateEmailError from exc
    session = await issue_session(user, settings, repository)
    if not requires_verification:
        return session
    if delivery is None:
        raise RuntimeError("이메일 전달 서비스를 초기화하지 못했습니다.")
    verification_token, _ = await issue_one_time_token(
        user_id=user.id,
        purpose="email_verification",
        lifetime_minutes=settings.taskview_email_token_minutes,
        settings=settings,
        repository=repository,
        recipient_email=str(user.email),
        delivery=delivery,
    )
    session.verification_token = delivery.development_token(verification_token)
    return session


async def resend_email_verification(
    user: UserPublic, settings: Settings, repository: PostgresNeedexStore
) -> TokenDeliveryResponse:
    if not settings.taskview_require_email_verification:
        return TokenDeliveryResponse(accepted=True, expires_at=None, retry_after_seconds=0)
    if user.email_verified:
        return TokenDeliveryResponse(accepted=True, expires_at=None, retry_after_seconds=0)
    delivery = DeliveryService(settings)
    delivery.ensure_api_ready()
    token, expires_at = await issue_one_time_token(
        user_id=user.id,
        purpose="email_verification",
        lifetime_minutes=settings.taskview_email_token_minutes,
        settings=settings,
        repository=repository,
        recipient_email=str(user.email),
        delivery=delivery,
    )
    return TokenDeliveryResponse(
        expires_at=expires_at,
        development_token=delivery.development_token(token),
    )


async def confirm_email_verification(
    token: str, repository: PostgresNeedexStore
) -> UserPublic | None:
    return await repository.confirm_email_verification(hash_session_token(token))


async def request_password_reset(
    email: str, settings: Settings, repository: PostgresNeedexStore
) -> TokenDeliveryResponse:
    delivery = DeliveryService(settings)
    delivery.ensure_api_ready()
    record = await repository.get_user_for_auth(email)
    if record is not None and record.is_active:
        await issue_one_time_token(
            user_id=record.user.id,
            purpose="password_reset",
            lifetime_minutes=settings.taskview_password_reset_minutes,
            settings=settings,
            repository=repository,
            recipient_email=str(record.user.email),
            delivery=delivery,
        )
    return TokenDeliveryResponse(
        accepted=True,
        expires_at=None,
        retry_after_seconds=60,
        development_token=None,
    )


async def reset_password(
    token: str,
    new_password: str,
    settings: Settings,
    repository: PostgresNeedexStore,
) -> AuthSessionResponse | None:
    user = await repository.reset_password_with_token(
        hash_session_token(token), password_hash.hash(new_password)
    )
    if user is None:
        return None
    return await issue_session(user, settings, repository)


async def start_google_oauth(
    settings: Settings, repository: PostgresNeedexStore
) -> OAuthStartResponse:
    if not settings.taskview_google_client_id or not settings.taskview_google_client_secret:
        raise OAuthConfigurationError
    state = secrets.token_urlsafe(48)
    await repository.create_oauth_state(
        token_hash=hash_session_token(state),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    query = urlencode(
        {
            "client_id": settings.taskview_google_client_id,
            "redirect_uri": settings.taskview_google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "prompt": "select_account",
        }
    )
    return OAuthStartResponse(
        authorization_url=f"https://accounts.google.com/o/oauth2/v2/auth?{query}"
    )


async def complete_google_oauth(
    *,
    code: str,
    state: str,
    settings: Settings,
    repository: PostgresNeedexStore,
) -> AuthSessionResponse:
    if not settings.taskview_google_client_id or not settings.taskview_google_client_secret:
        raise OAuthConfigurationError
    if not await repository.consume_oauth_state(hash_session_token(state)):
        raise OAuthExchangeError("OAuth state가 만료되었거나 이미 사용되었습니다.")
    async with httpx.AsyncClient(timeout=10) as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.taskview_google_client_id,
                "client_secret": settings.taskview_google_client_secret,
                "redirect_uri": settings.taskview_google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        if token_response.status_code != 200:
            raise OAuthExchangeError("Google 인증 코드를 교환하지 못했습니다.")
        access_token = token_response.json().get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OAuthExchangeError("Google access token이 없습니다.")
        user_response = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"authorization": f"Bearer {access_token}"},
        )
        if user_response.status_code != 200:
            raise OAuthExchangeError("Google 사용자 정보를 확인하지 못했습니다.")
    profile = user_response.json()
    subject = profile.get("sub")
    email = profile.get("email")
    email_verified = profile.get("email_verified")
    if not isinstance(subject, str) or not isinstance(email, str) or email_verified is not True:
        raise OAuthExchangeError("검증된 Google 이메일이 필요합니다.")
    display_name = profile.get("name")
    if not isinstance(display_name, str) or len(display_name.strip()) < 2:
        display_name = email.split("@", 1)[0]
    user = await repository.get_or_create_google_user(
        subject=subject,
        email=email,
        display_name=display_name.strip()[:80],
        unusable_password_hash=password_hash.hash(secrets.token_urlsafe(48)),
    )
    return await issue_session(user, settings, repository)


async def log_in(
    request: LoginRequest, settings: Settings, repository: PostgresNeedexStore
) -> AuthSessionResponse:
    record = await repository.get_user_for_auth(str(request.email))
    encoded_password = record.password_hash if record else dummy_password_hash
    valid_password = verify_password(request.password, encoded_password)

    if record and record.locked_until and record.locked_until > datetime.now(UTC):
        raise AccountLockedError
    if not record or not record.is_active or not valid_password:
        if record:
            await repository.record_login_failure(
                record.user.id,
                max_failures=settings.taskview_login_max_failures,
                lock_minutes=settings.taskview_login_lock_minutes,
            )
        raise InvalidCredentialsError

    await repository.record_login_success(record.user.id)
    user = record.user
    if not settings.taskview_require_email_verification and not user.email_verified:
        user = await repository.mark_email_verified(user.id)
    return await issue_session(user, settings, repository)


async def rotate_session(
    token: str, user: UserPublic, settings: Settings, repository: PostgresNeedexStore
) -> AuthSessionResponse:
    await repository.revoke_session(hash_session_token(token))
    return await issue_session(user, settings, repository)


async def authenticate_session(token: str, repository: PostgresNeedexStore) -> UserPublic | None:
    if len(token) < 40:
        return None
    return await repository.get_user_by_session(hash_session_token(token))


async def revoke_session(token: str, repository: PostgresNeedexStore) -> None:
    await repository.revoke_session(hash_session_token(token))


async def get_session_credentials(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    return credentials.credentials


async def get_current_user(
    token: Annotated[str, Depends(get_session_credentials)],
) -> UserPublic:
    user = await authenticate_session(token, store)
    if user is None:
        raise HTTPException(status_code=401, detail="세션이 만료되었거나 유효하지 않습니다.")
    if not get_settings().taskview_require_email_verification and not user.email_verified:
        user = await store.mark_email_verified(user.id)
    return user


CurrentUser = Annotated[UserPublic, Depends(get_current_user)]
SessionToken = Annotated[str, Depends(get_session_credentials)]


async def get_verified_user(user: CurrentUser) -> UserPublic:
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="이메일 확인이 필요합니다.")
    return user


VerifiedUser = Annotated[UserPublic, Depends(get_verified_user)]


@dataclass(frozen=True)
class WorkspacePrincipal:
    user: UserPublic
    workspace_id: str
    member_role: Role


@dataclass(frozen=True)
class WorkspaceApiKeyPrincipal:
    key_id: str
    workspace_id: str
    scopes: frozenset[str]


async def _resolve_business_principal(user: UserPublic) -> WorkspacePrincipal:
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="이메일 확인이 필요합니다.")
    if user.onboarding_status != "complete":
        raise HTTPException(status_code=409, detail="워크스페이스 온보딩을 완료해야 합니다.")
    membership = await store.get_current_workspace_membership(
        user.id, require_onboarding_complete=True
    )
    if membership is None:
        raise HTTPException(status_code=409, detail="활성 워크스페이스 멤버십이 필요합니다.")
    return WorkspacePrincipal(
        user=user,
        workspace_id=membership.workspace_id,
        member_role=membership.role,
    )


async def get_business_principal(user: CurrentUser) -> WorkspacePrincipal:
    return await _resolve_business_principal(user)


BusinessPrincipal = Annotated[WorkspacePrincipal, Depends(get_business_principal)]


async def get_business_user(principal: BusinessPrincipal) -> UserPublic:
    return principal.user


BusinessUser = Annotated[UserPublic, Depends(get_business_user)]


def require_workspace_roles(*allowed_roles: Role):
    async def role_dependency(principal: BusinessPrincipal) -> WorkspacePrincipal:
        if principal.member_role not in allowed_roles:
            raise HTTPException(status_code=403, detail="이 작업을 수행할 권한이 없습니다.")
        return principal

    return role_dependency


WorkspaceOwner = Annotated[
    WorkspacePrincipal, Depends(require_workspace_roles("data_owner", "admin"))
]
WorkspaceAdmin = Annotated[WorkspacePrincipal, Depends(require_workspace_roles("admin"))]


NeedexAccessPrincipal = WorkspacePrincipal | WorkspaceApiKeyPrincipal


async def get_taskview_access_principal(
    token: Annotated[str, Depends(get_session_credentials)],
) -> NeedexAccessPrincipal:
    if token.startswith(API_KEY_PREFIX):
        if len(token) < 40:
            raise HTTPException(status_code=401, detail="API 키가 유효하지 않습니다.")
        record: WorkspaceApiKeyRecord | None = await store.authenticate_workspace_api_key(
            hash_session_token(token)
        )
        if record is None:
            raise HTTPException(
                status_code=401,
                detail="API 키가 만료되었거나 폐기되었거나 유효하지 않습니다.",
            )
        return WorkspaceApiKeyPrincipal(
            key_id=record.id,
            workspace_id=record.workspace_id,
            scopes=frozenset(record.scopes),
        )

    user = await authenticate_session(token, store)
    if user is None:
        raise HTTPException(status_code=401, detail="세션이 만료되었거나 유효하지 않습니다.")
    return await _resolve_business_principal(user)


AnyNeedexAccessPrincipal = Annotated[NeedexAccessPrincipal, Depends(get_taskview_access_principal)]


def require_taskview_scope(scope: ApiKeyScope):
    async def scope_dependency(
        principal: AnyNeedexAccessPrincipal,
    ) -> NeedexAccessPrincipal:
        if isinstance(principal, WorkspaceApiKeyPrincipal) and scope not in principal.scopes:
            raise HTTPException(
                status_code=403,
                detail=f"API 키에 필요한 scope가 없습니다: {scope}",
            )
        return principal

    return scope_dependency


NeedexArtifactsPrincipal = Annotated[
    NeedexAccessPrincipal,
    Depends(require_taskview_scope("taskviews:artifacts:read")),
]
NeedexDataPrincipal = Annotated[
    NeedexAccessPrincipal,
    Depends(require_taskview_scope("taskviews:data:read")),
]
NeedexAnalyticsPrincipal = Annotated[
    NeedexAccessPrincipal,
    Depends(require_taskview_scope("taskviews:analytics:read")),
]


def current_settings() -> Settings:
    return get_settings()
