import csv
import io
import json
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import NoReturn

import asyncpg
import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .admin import (
    build_account_ui,
    build_approval_inbox,
    build_audit_ui,
    build_data_source_detail,
    build_data_sources_overview,
    build_integrations_ui,
    build_team_ui,
    build_workspace_data_source_detail,
    build_workspace_ui,
    default_policy_ui,
)
from .admin_schemas import (
    ApiKeyCreated,
    ApiKeyCreateRequest,
    ApiKeySummary,
    DataSourceConnectionRequest,
    DataSourceConnectionTest,
    DataSourceScanCompleteRequest,
    DataSourceScanCompleteResponse,
    DataSourceScanResponse,
    UiAccountPatch,
    UiAccountPayload,
    UiApprovalInbox,
    UiAuditEvent,
    UiDataSourceDetail,
    UiDataSourcesPayload,
    UiEvidencePayload,
    UiIntegrationSettings,
    UiPolicySettings,
    UiTeamInvitation,
    UiTeamMember,
    UiWorkspaceSettings,
)
from .ai_client import request_business_intent
from .auth import (
    AccountLockedError,
    BusinessPrincipal,
    CurrentUser,
    DuplicateEmailError,
    InvalidCredentialsError,
    NeedexAccessPrincipal,
    NeedexAnalyticsPrincipal,
    NeedexArtifactsPrincipal,
    NeedexDataPrincipal,
    SessionToken,
    WorkspaceAdmin,
    WorkspaceApiKeyPrincipal,
    WorkspaceOwner,
    WorkspacePrincipal,
    confirm_email_verification,
    hash_session_token,
    log_in,
    request_password_reset,
    resend_email_verification,
    reset_password,
    revoke_session,
    rotate_session,
    sign_up,
)
from .auth_schemas import (
    AuthSessionResponse,
    EmailVerificationConfirmRequest,
    EmailVerificationStatus,
    LoginRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    SignUpRequest,
    TokenDeliveryResponse,
    UserPublic,
)
from .config import get_settings
from .data_source_runtime import (
    CatalogScanError,
    CatalogScanResult,
    DataSourceConnectionError,
    DataSourceRuntimeConfig,
    DataSourceRuntimeError,
    HostNotAllowedError,
    PeerVerificationError,
    PostgreSQLConnectionSpec,
    ReadOnlyEnforcementError,
    TlsRequiredError,
    TlsVerificationError,
    UnsupportedEngineError,
    scan_catalog,
)
from .data_source_runtime import (
    test_connection as test_data_source_connection,
)
from .experience import (
    NeedexExpiredError,
    build_approval_review,
    build_artifacts,
    build_compilation,
    build_dashboard,
    build_data_response,
    interpret_purpose,
    is_approval_submission_allowed,
    list_data_sources,
)
from .experience_schemas import (
    ApprovalDecisionRequest,
    ApprovalReview,
    AuditEvent,
    CompilationResponse,
    DashboardResponse,
    DataResponse,
    DataSource,
    NeedexArtifacts,
    PurposeInterpretation,
    PurposeInterpretationRequest,
)
from .journey import build_analytics, build_approval_status, build_discovery
from .journey_schemas import (
    ApprovalStatusResponse,
    ApprovalSubmission,
    DiscoveryResponse,
    NeedexAnalytics,
)
from .mailer import DeliveryConfigurationError, DeliveryService
from .schemas import (
    DecisionRequest,
    EvidenceContract,
    HealthResponse,
    NeedexResponse,
    PreviewRequest,
    RefineRequest,
)
from .service import (
    NeedexConflictError,
    NeedexNotFoundError,
    approve_recommended_alternative,
    create_preview,
    decide,
    refine,
)
from .store import (
    DataSourceScanJobConsumedError,
    DataSourceScanJobExpiredError,
    DataSourceScanJobInput,
    DataSourceScanJobNotFoundError,
    InvitationEmailMismatchError,
    InvitationInvalidError,
    SubmissionSnapshotConflictError,
    WorkspaceApiKeyRecord,
    store,
)
from .workspace_schemas import (
    AccountPatch,
    AccountPublic,
    BatchInvitationRequest,
    BatchInvitationResponse,
    NotificationSettings,
    OnboardingCompleteRequest,
    WorkspaceCreate,
    WorkspaceInvitationAcceptRequest,
    WorkspaceMember,
    WorkspacePatch,
    WorkspacePublic,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await store.start()
    delivery = DeliveryService(get_settings())
    await delivery.start_worker(store)
    try:
        yield
    finally:
        await delivery.stop_worker()
        await store.stop()


app = FastAPI(title="Needex BE", version="0.4.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in get_settings().taskview_cors_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _disable_sensitive_response_caching(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _api_key_summary(record: WorkspaceApiKeyRecord) -> ApiKeySummary:
    now = datetime.now(UTC)
    if record.revoked_at is not None:
        key_status = "revoked"
    elif record.expires_at is None or record.expires_at <= now:
        key_status = "expired"
    else:
        key_status = "active"
    return ApiKeySummary(
        id=record.id,
        name=record.name,
        keyPrefix=record.key_prefix,
        scopes=list(record.scopes),
        createdAt=record.created_at,
        expiresAt=record.expires_at,
        lastUsedAt=record.last_used_at,
        revokedAt=record.revoked_at,
        revokedBy=record.revoked_by,
        status=key_status,
    )


def _csv_values(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _data_source_runtime_config() -> DataSourceRuntimeConfig:
    settings = get_settings()
    try:
        return DataSourceRuntimeConfig(
            allowed_hostnames=frozenset(
                _csv_values(settings.taskview_data_source_allowed_hostnames)
            ),
            allowed_cidrs=_csv_values(settings.taskview_data_source_allowed_cidrs),
            require_tls=settings.taskview_data_source_require_tls,
            verify_tls=settings.taskview_data_source_verify_tls,
            tls_ca_file=settings.taskview_data_source_tls_ca_file,
            connect_timeout_seconds=(settings.taskview_data_source_connect_timeout_seconds),
            command_timeout_seconds=(settings.taskview_data_source_command_timeout_seconds),
            close_timeout_seconds=settings.taskview_data_source_close_timeout_seconds,
            max_catalog_fields=settings.taskview_data_source_max_catalog_fields,
        )
    except ValueError:
        raise HTTPException(
            status_code=503,
            detail="데이터 소스 보안 설정을 사용할 수 없습니다.",
        ) from None


def _data_source_spec(
    request: DataSourceConnectionRequest,
    config: DataSourceRuntimeConfig,
) -> PostgreSQLConnectionSpec:
    return PostgreSQLConnectionSpec(
        engine=request.engine,
        host=request.host,
        port=int(request.port),
        database=request.database,
        username=request.username,
        password=request.password.get_secret_value(),
        tls=config.require_tls if request.tls is None else request.tls,
    )


def _raise_data_source_runtime_error(error: DataSourceRuntimeError) -> NoReturn:
    if isinstance(error, UnsupportedEngineError):
        status_code = 422
        detail = "현재 PostgreSQL 데이터 소스만 지원합니다."
    elif isinstance(error, (HostNotAllowedError, PeerVerificationError)):
        status_code = 403
        detail = "허용되지 않은 데이터베이스 호스트입니다."
    elif isinstance(
        error,
        (TlsRequiredError, TlsVerificationError, ReadOnlyEnforcementError),
    ):
        status_code = 409
        detail = "TLS 또는 읽기 전용 연결 정책을 충족하지 못했습니다."
    elif isinstance(error, (DataSourceConnectionError, CatalogScanError)):
        status_code = 503
        detail = "데이터베이스 메타데이터 연결을 완료하지 못했습니다."
    else:
        status_code = 503
        detail = "데이터 소스 작업을 완료하지 못했습니다."
    raise HTTPException(status_code=status_code, detail=detail) from None


def _encrypt_data_source_credentials(request: DataSourceConnectionRequest) -> bytes:
    key = get_settings().taskview_data_source_encryption_key
    if key is None:
        raise HTTPException(
            status_code=503,
            detail="데이터 소스 자격 증명 암호화가 설정되지 않았습니다.",
        )
    payload = json.dumps(
        {
            "version": 1,
            "username": request.username,
            "password": request.password.get_secret_value(),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    try:
        return Fernet(key.get_secret_value().encode()).encrypt(payload)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=503,
            detail="데이터 소스 자격 증명 암호화를 사용할 수 없습니다.",
        ) from None


def _catalog_payload(result: CatalogScanResult) -> list[dict[str, object]]:
    return [
        {
            "schema": table.schema,
            "name": table.name,
            "fields": [
                {
                    "schema": field.schema,
                    "table": field.table,
                    "name": field.name,
                    "data_type": field.data_type,
                    "nullable": field.nullable,
                    "ordinal_position": field.ordinal_position,
                    "sensitive_name": field.sensitive_name,
                    "sensitivity_reason": field.sensitivity_reason,
                }
                for field in table.fields
            ],
        }
        for table in result.catalog
    ]


@app.exception_handler(asyncpg.PostgresError)
async def postgres_error_handler(_request: Request, _exc: asyncpg.PostgresError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "데이터베이스를 사용할 수 없습니다."})


@app.exception_handler(DeliveryConfigurationError)
async def delivery_configuration_error_handler(
    _request: Request, exc: DeliveryConfigurationError
) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    await store.ping()
    return HealthResponse(ai_url=get_settings().taskview_ai_url)


@app.get("/ready")
async def ready() -> dict[str, str]:
    await store.ping()
    DeliveryService(get_settings()).ensure_api_ready()
    return {"status": "ready", "delivery": "smtp-outbox"}


@app.post(
    "/v1/auth/signup",
    response_model=AuthSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def signup(request: SignUpRequest) -> AuthSessionResponse:
    try:
        return await sign_up(request, get_settings(), store)
    except DuplicateEmailError as exc:
        raise HTTPException(status_code=409, detail="이미 가입된 이메일입니다.") from exc


@app.post("/v1/auth/login", response_model=AuthSessionResponse)
async def login(request: LoginRequest) -> AuthSessionResponse:
    try:
        return await log_in(request, get_settings(), store)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다."
        ) from exc
    except AccountLockedError as exc:
        raise HTTPException(
            status_code=429,
            detail="로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.",
        ) from exc


@app.get("/v1/auth/me", response_model=UserPublic)
async def me(user: CurrentUser) -> UserPublic:
    return user


@app.post("/v1/auth/session/refresh", response_model=AuthSessionResponse)
async def refresh_session(token: SessionToken, user: CurrentUser) -> AuthSessionResponse:
    return await rotate_session(token, user, get_settings(), store)


@app.post("/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(token: SessionToken) -> Response:
    await revoke_session(token, store)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/v1/auth/email-verifications/status", response_model=EmailVerificationStatus)
async def email_verification_status(user: CurrentUser) -> EmailVerificationStatus:
    return EmailVerificationStatus(
        email=user.email,
        verified=user.email_verified,
        onboarding_status=user.onboarding_status,
    )


@app.post(
    "/v1/auth/email-verifications/resend",
    response_model=TokenDeliveryResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def resend_verification(user: CurrentUser) -> TokenDeliveryResponse:
    return await resend_email_verification(user, get_settings(), store)


@app.post("/v1/auth/email-verifications/confirm", response_model=EmailVerificationStatus)
async def confirm_verification(
    request: EmailVerificationConfirmRequest,
) -> EmailVerificationStatus:
    user = await confirm_email_verification(request.token, store)
    if user is None:
        raise HTTPException(status_code=400, detail="인증 링크가 만료되었거나 이미 사용되었습니다.")
    return EmailVerificationStatus(
        email=user.email,
        verified=user.email_verified,
        onboarding_status=user.onboarding_status,
    )


@app.post(
    "/v1/auth/password-reset-requests",
    response_model=TokenDeliveryResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_password_reset(request: PasswordResetRequest) -> TokenDeliveryResponse:
    return await request_password_reset(str(request.email), get_settings(), store)


@app.post("/v1/auth/password-resets", response_model=AuthSessionResponse)
async def complete_password_reset(
    request: PasswordResetConfirmRequest,
) -> AuthSessionResponse:
    session = await reset_password(request.token, request.new_password, get_settings(), store)
    if session is None:
        raise HTTPException(
            status_code=400, detail="재설정 링크가 만료되었거나 이미 사용되었습니다."
        )
    return session


@app.post("/v1/workspaces", response_model=WorkspacePublic, status_code=status.HTTP_201_CREATED)
async def create_workspace(request: WorkspaceCreate, user: CurrentUser) -> WorkspacePublic:
    if not user.email_verified:
        raise HTTPException(
            status_code=409, detail="이메일 확인 후 워크스페이스를 만들 수 있습니다."
        )
    return await store.create_workspace(
        user_id=user.id,
        name=request.name,
        region=request.region,
        default_ttl_days=request.default_ttl_days,
        member_role=request.member_role,
    )


@app.get("/v1/workspace", response_model=WorkspacePublic)
async def get_workspace(user: CurrentUser) -> WorkspacePublic:
    workspace = await store.get_workspace_for_user(user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    return workspace


@app.patch("/v1/workspace", response_model=WorkspacePublic)
async def patch_workspace(request: WorkspacePatch, principal: WorkspaceAdmin) -> WorkspacePublic:
    workspace = await store.get_workspace_for_user(principal.user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    updated = await store.update_workspace(
        workspace.id, principal.user.id, request.model_dump(exclude_none=True)
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
    return updated


@app.patch("/v1/workspace/notifications", response_model=WorkspacePublic)
async def patch_workspace_notifications(
    request: NotificationSettings, principal: WorkspaceAdmin
) -> WorkspacePublic:
    workspace = await store.get_workspace_for_user(principal.user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    updated = await store.update_workspace_notifications(workspace.id, principal.user.id, request)
    if updated is None:
        raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
    return updated


@app.post(
    "/v1/workspaces/{workspace_id}/invitations:batch",
    response_model=BatchInvitationResponse,
)
async def invite_workspace_members(
    workspace_id: str, request: BatchInvitationRequest, user: CurrentUser
) -> BatchInvitationResponse:
    if workspace_id == "current":
        current_workspace = await store.get_workspace_for_user(user.id)
        if current_workspace is None:
            raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
        workspace_id = current_workspace.id
    delivery = DeliveryService(get_settings())
    delivery.ensure_api_ready()
    expires_at = datetime.now(UTC) + timedelta(days=7)
    prepared = []
    development_tokens: dict[str, str] = {}
    for invitation in request.invitations:
        email = str(invitation.email).lower()
        raw_token = secrets.token_urlsafe(48)
        development_tokens.setdefault(email, raw_token)
        prepared.append(
            (
                email,
                invitation.role,
                hash_session_token(raw_token),
                delivery.encrypt_token(raw_token),
                expires_at,
            )
        )
    result = await store.create_workspace_invitations(
        workspace_id=workspace_id,
        invited_by=user.id,
        invitations=prepared,
        onboarding_only=True,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
    if get_settings().taskview_expose_dev_tokens:
        for invitation in result.results:
            if invitation.status == "invited":
                invitation.development_token = development_tokens[str(invitation.email)]
    return result


@app.post("/v1/workspace-invitations/accept", response_model=WorkspacePublic)
async def accept_workspace_invitation(
    request: WorkspaceInvitationAcceptRequest, user: CurrentUser
) -> WorkspacePublic:
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="이메일 확인이 필요합니다.")
    try:
        return await store.accept_workspace_invitation(
            token_hash=hash_session_token(request.token),
            user_id=user.id,
            user_email=str(user.email),
        )
    except InvitationEmailMismatchError as exc:
        raise HTTPException(
            status_code=403, detail="초대 이메일과 로그인 이메일이 일치하지 않습니다."
        ) from exc
    except InvitationInvalidError as exc:
        raise HTTPException(
            status_code=400, detail="초대 링크가 만료되었거나 이미 사용되었습니다."
        ) from exc


@app.post(
    "/v1/workspaces/{workspace_id}/onboarding/complete",
    response_model=WorkspacePublic,
)
async def complete_workspace_onboarding(
    workspace_id: str,
    _request: OnboardingCompleteRequest,
    user: CurrentUser,
) -> WorkspacePublic:
    if workspace_id == "current":
        current_workspace = await store.get_workspace_for_user(user.id)
        if current_workspace is None:
            raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
        workspace_id = current_workspace.id
    workspace = await store.complete_workspace_onboarding(workspace_id, user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
    return workspace


@app.get("/v1/members", response_model=list[WorkspaceMember])
async def list_members(principal: BusinessPrincipal) -> list[WorkspaceMember]:
    members = await store.list_workspace_members(principal.user.id)
    if members is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    return members


@app.get("/v1/account", response_model=AccountPublic)
async def get_account(user: CurrentUser) -> AccountPublic:
    return AccountPublic.model_validate(user.model_dump())


@app.patch("/v1/account", response_model=AccountPublic)
async def patch_account(request: AccountPatch, user: CurrentUser) -> AccountPublic:
    updated = await store.update_account_name(user.id, request.display_name)
    if updated is None:
        raise HTTPException(status_code=404, detail="계정을 찾을 수 없습니다.")
    return AccountPublic.model_validate(updated.model_dump())


@app.get("/v1/ui/data-sources", response_model=UiDataSourcesPayload)
async def ui_data_sources(principal: BusinessPrincipal) -> UiDataSourcesPayload:
    views = await store.list_views_for_member(
        user_id=principal.user.id,
        workspace_id=principal.workspace_id,
        limit=100,
    )
    active_count = sum(view.status == "approved" for view in views)
    workspace_sources = await store.list_workspace_data_sources(
        workspace_id=principal.workspace_id,
        user_id=principal.user.id,
    )
    snapshots = await store.list_public_demo_snapshots()
    return build_data_sources_overview(active_count, workspace_sources, snapshots)


@app.get("/v1/ui/data-sources/{source_id}", response_model=UiDataSourceDetail)
async def ui_data_source_detail(source_id: str, principal: BusinessPrincipal) -> UiDataSourceDetail:
    source = build_data_source_detail(source_id)
    if source is not None:
        return source
    workspace_source = await store.get_workspace_data_source(
        source_id,
        workspace_id=principal.workspace_id,
        user_id=principal.user.id,
    )
    if workspace_source is None:
        raise HTTPException(status_code=404, detail="데이터 소스를 찾을 수 없습니다.")
    return build_workspace_data_source_detail(workspace_source)


@app.post("/v1/ui/data-sources/test", response_model=DataSourceConnectionTest)
async def ui_test_data_source(
    request: DataSourceConnectionRequest, _principal: WorkspaceOwner
) -> DataSourceConnectionTest:
    config = _data_source_runtime_config()
    try:
        result = await test_data_source_connection(
            _data_source_spec(request, config),
            config,
        )
    except DataSourceRuntimeError as error:
        _raise_data_source_runtime_error(error)
    return DataSourceConnectionTest(
        success=result.success,
        read_only=result.read_only,
        tls=result.tls,
        latency_ms=result.latency_ms,
        message="PostgreSQL 연결을 읽기 전용으로 안전하게 확인했습니다.",
    )


@app.post("/v1/ui/data-sources/scan", response_model=DataSourceScanResponse)
async def ui_scan_data_source(
    request: DataSourceConnectionRequest, principal: WorkspaceOwner
) -> DataSourceScanResponse:
    config = _data_source_runtime_config()
    credential_ciphertext = _encrypt_data_source_credentials(request)
    try:
        result = await scan_catalog(_data_source_spec(request, config), config)
    except DataSourceRuntimeError as error:
        _raise_data_source_runtime_error(error)
    settings = get_settings()
    if not 30 <= settings.taskview_data_source_scan_job_ttl_seconds <= 3600:
        raise HTTPException(
            status_code=503,
            detail="데이터 소스 스캔 보존 설정을 사용할 수 없습니다.",
        )
    try:
        job_id = await store.create_data_source_scan_job(
            workspace_id=principal.workspace_id,
            created_by=principal.user.id,
            job=DataSourceScanJobInput(
                name=request.name,
                organization=request.organization,
                engine="PostgreSQL",
                connection_metadata={
                    "engine": "PostgreSQL",
                    "host": request.host,
                    "port": int(request.port),
                    "database": request.database,
                    "tls": config.require_tls if request.tls is None else request.tls,
                },
                credential_ciphertext=credential_ciphertext,
                table_count=result.table_count,
                field_count=result.field_count,
                sensitive_field_count=result.sensitive_field_count,
                raw_rows_returned=result.raw_rows_returned,
                catalog=_catalog_payload(result),
                expires_at=datetime.now(UTC)
                + timedelta(seconds=settings.taskview_data_source_scan_job_ttl_seconds),
            ),
        )
    except DataSourceScanJobNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="워크스페이스 데이터 소스 권한을 찾을 수 없습니다.",
        ) from None
    return DataSourceScanResponse(
        job_id=job_id,
        table_count=result.table_count,
        field_count=result.field_count,
        sensitive_field_count=result.sensitive_field_count,
        raw_rows_returned=result.raw_rows_returned,
    )


@app.post(
    "/v1/ui/data-sources/scan/complete",
    response_model=DataSourceScanCompleteResponse,
)
async def ui_complete_data_source_scan(
    request: DataSourceScanCompleteRequest, principal: WorkspaceOwner
) -> DataSourceScanCompleteResponse:
    try:
        source = await store.complete_data_source_scan_job(
            job_id=str(request.job_id),
            workspace_id=principal.workspace_id,
            created_by=principal.user.id,
            owner=request.owner,
            region=request.region,
            policy=request.policy,
        )
    except DataSourceScanJobNotFoundError:
        raise HTTPException(status_code=404, detail="스캔 작업을 찾을 수 없습니다.") from None
    except DataSourceScanJobExpiredError:
        raise HTTPException(status_code=410, detail="스캔 작업이 만료되었습니다.") from None
    except DataSourceScanJobConsumedError:
        raise HTTPException(status_code=409, detail="이미 완료된 스캔 작업입니다.") from None
    return DataSourceScanCompleteResponse(source_id=source.id)


@app.get("/v1/ui/approval-inbox", response_model=UiApprovalInbox)
async def ui_approval_inbox(principal: WorkspaceOwner) -> UiApprovalInbox:
    views = await store.list_submitted_views_for_approver(
        user_id=principal.user.id,
        workspace_id=principal.workspace_id,
        limit=100,
    )
    return build_approval_inbox(views, principal.user)


@app.get("/v1/ui/audit-events", response_model=list[UiAuditEvent])
async def ui_audit_events(principal: BusinessPrincipal) -> list[UiAuditEvent]:
    views = await store.list_views_for_member(
        user_id=principal.user.id,
        workspace_id=principal.workspace_id,
        limit=100,
    )
    events_by_view = {
        view.id: await store.list_audit_events(
            view.id, workspace_id=principal.workspace_id, limit=100
        )
        for view in views
    }
    return build_audit_ui(views, events_by_view)


@app.get("/v1/ui/evidence-contracts/{evidence_id}", response_model=UiEvidencePayload)
async def ui_evidence_contract(evidence_id: str, principal: BusinessPrincipal) -> UiEvidencePayload:
    view = await get_authorized_view(evidence_id, principal)
    evidence = view.evidence
    if evidence is None or evidence.view_id != evidence_id:
        raise HTTPException(status_code=404, detail="Evidence Contract를 찾을 수 없습니다.")
    return UiEvidencePayload(
        id=evidence.view_id,
        view=build_artifacts(view).view_name,
        title="JP Signup UX Diagnosis",
        created=evidence.created_at.strftime("%Y.%m.%d %H:%M"),
        hash=f"{evidence.content_sha256[:4]}…{evidence.content_sha256[-4:]}",
    )


@app.get("/v1/ui/settings/workspace", response_model=UiWorkspaceSettings)
async def ui_workspace_settings(principal: BusinessPrincipal) -> UiWorkspaceSettings:
    workspace = await store.get_workspace_for_user(principal.user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    return build_workspace_ui(workspace)


@app.patch("/v1/ui/settings/workspace", response_model=UiWorkspaceSettings)
async def ui_patch_workspace_settings(
    request: UiWorkspaceSettings, principal: WorkspaceAdmin
) -> UiWorkspaceSettings:
    user = principal.user
    workspace = await store.get_workspace_for_user(user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    regions = {
        "Seoul · KR": "KR-11",
        "Tokyo · JP": "JP-13",
        "HCMC · VN": "VN-SG",
        "Global": "GLOBAL",
    }
    outputs = {
        "Dashboard": "dashboard",
        "API": "api",
        "Dashboard + API": "dashboard_api",
    }
    ttl_digits = "".join(character for character in request.ttl if character.isdigit())
    updated = await store.update_workspace(
        workspace.id,
        user.id,
        {
            "name": request.name,
            "region": regions.get(request.region, workspace.region),
            "default_ttl_days": int(ttl_digits or workspace.default_ttl_days),
            "default_output_mode": outputs.get(request.output, workspace.default_output_mode),
        },
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="워크스페이스를 찾을 수 없습니다.")
    updated = await store.update_workspace_notifications(
        updated.id,
        user.id,
        NotificationSettings(
            approval_requested=request.notifications.approval,
            view_approved=request.notifications.approved,
            ttl_expiring=request.notifications.expiry,
            audit_events=request.notifications.audit,
        ),
    )
    assert updated is not None
    return build_workspace_ui(updated)


@app.get("/v1/ui/settings/policy", response_model=UiPolicySettings)
async def ui_policy_settings(principal: BusinessPrincipal) -> UiPolicySettings:
    saved = await store.get_workspace_ui_setting(principal.user.id, "policy")
    return UiPolicySettings.model_validate(saved) if saved else default_policy_ui()


@app.patch("/v1/ui/settings/policy", response_model=UiPolicySettings)
async def ui_patch_policy_settings(
    request: UiPolicySettings, principal: WorkspaceOwner
) -> UiPolicySettings:
    if not await store.set_workspace_ui_setting(principal.user.id, "policy", request.model_dump()):
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    return request


@app.get("/v1/ui/settings/team", response_model=list[UiTeamMember])
async def ui_team_settings(principal: BusinessPrincipal) -> list[UiTeamMember]:
    members = await store.list_workspace_members(principal.user.id)
    if members is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    return build_team_ui(members)


@app.post("/v1/ui/settings/team", response_model=BatchInvitationResponse)
async def ui_invite_team_member(
    request: UiTeamInvitation, principal: WorkspaceAdmin
) -> BatchInvitationResponse:
    workspace = await store.get_workspace_for_user(principal.user.id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    roles = {
        "Product / UX": "requester",
        "Data Owner": "data_owner",
        "Security / Admin": "admin",
    }
    delivery = DeliveryService(get_settings())
    delivery.ensure_api_ready()
    raw_token = secrets.token_urlsafe(48)
    result = await store.create_workspace_invitations(
        workspace_id=workspace.id,
        invited_by=principal.user.id,
        invitations=[
            (
                str(request.email).lower(),
                roles[request.role],
                hash_session_token(raw_token),
                delivery.encrypt_token(raw_token),
                datetime.now(UTC) + timedelta(days=7),
            )
        ],
    )
    assert result is not None
    if get_settings().taskview_expose_dev_tokens and result.results:
        result.results[0].development_token = raw_token
    return result


@app.get("/v1/ui/settings/integrations", response_model=UiIntegrationSettings)
async def ui_integration_settings(
    response: Response, principal: WorkspaceAdmin
) -> UiIntegrationSettings:
    _disable_sensitive_response_caching(response)
    records = await store.list_workspace_api_keys(principal.workspace_id)
    now = datetime.now(UTC)
    active = next(
        (
            record
            for record in records
            if record.revoked_at is None
            and record.expires_at is not None
            and record.expires_at > now
        ),
        None,
    )
    return build_integrations_ui(active)


@app.get("/v1/ui/settings/integrations/keys", response_model=list[ApiKeySummary])
async def ui_list_api_keys(response: Response, principal: WorkspaceAdmin) -> list[ApiKeySummary]:
    _disable_sensitive_response_caching(response)
    records = await store.list_workspace_api_keys(principal.workspace_id)
    return [_api_key_summary(record) for record in records]


@app.post(
    "/v1/ui/settings/integrations/keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def ui_create_api_key(
    response: Response,
    principal: WorkspaceAdmin,
    request: ApiKeyCreateRequest | None = None,
) -> ApiKeyCreated:
    _disable_sensitive_response_caching(response)
    request = request or ApiKeyCreateRequest()
    if len(set(request.scopes)) != len(request.scopes):
        raise HTTPException(status_code=422, detail="API key scope는 중복될 수 없습니다.")
    secret = f"tv_live_{secrets.token_urlsafe(32)}"
    record = await store.create_workspace_api_key(
        workspace_id=principal.workspace_id,
        created_by=principal.user.id,
        name=request.name,
        key_prefix=secret[:16],
        secret_hash=hash_session_token(secret),
        scopes=tuple(request.scopes),
        expires_at=datetime.now(UTC) + timedelta(days=request.expiresInDays),
    )
    if record is None:
        raise HTTPException(status_code=404, detail="워크스페이스 설정이 필요합니다.")
    return ApiKeyCreated(**_api_key_summary(record).model_dump(), secret=secret)


@app.delete(
    "/v1/ui/settings/integrations/keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def ui_revoke_api_key(key_id: str, principal: WorkspaceAdmin) -> Response:
    record = await store.revoke_workspace_api_key(
        workspace_id=principal.workspace_id,
        key_id=key_id,
        revoked_by=principal.user.id,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="API 키를 찾을 수 없습니다.")
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/v1/ui/account", response_model=UiAccountPayload)
async def ui_account(user: CurrentUser) -> UiAccountPayload:
    return build_account_ui(user)


@app.patch("/v1/ui/account", response_model=UiAccountPayload)
async def ui_patch_account(request: UiAccountPatch, user: CurrentUser) -> UiAccountPayload:
    updated = await store.update_account_name(user.id, request.name)
    if updated is None:
        raise HTTPException(status_code=404, detail="계정을 찾을 수 없습니다.")
    return build_account_ui(updated)


@app.get("/v1/data-sources", response_model=list[DataSource])
async def data_sources(_principal: BusinessPrincipal) -> list[DataSource]:
    return list_data_sources(await store.list_public_demo_snapshots())


@app.post("/v1/purpose/interpret", response_model=PurposeInterpretation)
async def purpose_interpretation(
    request: PurposeInterpretationRequest, principal: BusinessPrincipal
) -> PurposeInterpretation:
    intent = None
    try:
        intent = await request_business_intent(request, get_settings())
    except (httpx.HTTPError, ValueError):
        pass
    return interpret_purpose(request, principal.user, intent)


@app.get("/v1/dashboard", response_model=DashboardResponse)
async def dashboard(
    principal: BusinessPrincipal,
    period_days: int = Query(default=7, ge=1, le=90),
) -> DashboardResponse:
    views = await store.list_views_for_member(
        user_id=principal.user.id,
        workspace_id=principal.workspace_id,
        limit=100,
    )
    sources = list_data_sources(await store.list_public_demo_snapshots())
    return build_dashboard(views, principal.user, period_days, data_sources=sources)


async def get_authorized_view(
    view_id: str,
    principal: WorkspacePrincipal,
    *,
    require_creator: bool = False,
    require_approver: bool = False,
    require_submission: bool = False,
) -> NeedexResponse:
    access = await store.get_view_for_member(
        view_id,
        principal.user.id,
        workspace_id=principal.workspace_id,
        require_creator=require_creator,
        require_approver=require_approver,
        require_submission=require_submission,
    )
    if access is None:
        raise HTTPException(status_code=404, detail="Task View를 찾을 수 없습니다.")
    return access.view


async def get_authorized_output_view(
    view_id: str, principal: NeedexAccessPrincipal
) -> NeedexResponse:
    if isinstance(principal, WorkspaceApiKeyPrincipal):
        view = await store.get(view_id, workspace_id=principal.workspace_id)
        if view is None:
            raise HTTPException(status_code=404, detail="Task View를 찾을 수 없습니다.")
        return view
    return await get_authorized_view(view_id, principal)


def enforce_api_key_output_mode(view: NeedexResponse, principal: NeedexAccessPrincipal) -> None:
    if isinstance(principal, WorkspaceApiKeyPrincipal) and view.output_mode == "dashboard":
        raise HTTPException(
            status_code=403,
            detail="Dashboard 전용 Task View는 API 키로 조회할 수 없습니다.",
        )


def enforce_output_availability(view: NeedexResponse) -> None:
    if view.status != "approved":
        raise HTTPException(status_code=409, detail="승인된 Task View만 출력을 제공할 수 있습니다.")
    if view.evidence is None:
        raise HTTPException(status_code=409, detail="Evidence Contract가 없는 Task View입니다.")
    if datetime.now(UTC) >= view.evidence.expires_at:
        raise HTTPException(
            status_code=410,
            detail="Task View의 TTL이 만료되어 데이터 접근이 중단되었습니다.",
        )


async def record_successful_api_key_use(principal: NeedexAccessPrincipal) -> None:
    if not isinstance(principal, WorkspaceApiKeyPrincipal):
        return
    recorded = await store.record_workspace_api_key_use(
        key_id=principal.key_id,
        workspace_id=principal.workspace_id,
    )
    if not recorded:
        raise HTTPException(
            status_code=401,
            detail="API 키가 만료되었거나 폐기되었거나 유효하지 않습니다.",
        )


async def enforce_separation_of_duties(view_id: str, principal: WorkspacePrincipal) -> None:
    submission = await store.get_submission(view_id, workspace_id=principal.workspace_id)
    if submission and submission.submitted_by == principal.user.id:
        raise HTTPException(
            status_code=403, detail="자신이 제출한 승인 요청은 직접 승인할 수 없습니다."
        )


@app.post("/v1/taskviews/preview", response_model=NeedexResponse)
async def preview(request: PreviewRequest, principal: BusinessPrincipal) -> NeedexResponse:
    try:
        return await create_preview(
            request,
            get_settings(),
            store,
            principal.user.id,
            principal.workspace_id,
            str(principal.user.email),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="AI 계획 서비스에 연결하지 못했습니다."
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="AI 계획 결과가 유효하지 않습니다.") from exc


@app.get("/v1/taskviews", response_model=list[NeedexResponse])
async def list_views(principal: BusinessPrincipal) -> list[NeedexResponse]:
    return await store.list_views_for_member(
        user_id=principal.user.id,
        workspace_id=principal.workspace_id,
    )


@app.get("/v1/taskviews/{view_id}", response_model=NeedexResponse)
async def get_view(view_id: str, principal: BusinessPrincipal) -> NeedexResponse:
    return await get_authorized_view(view_id, principal)


@app.post("/v1/taskviews/{view_id}/decision", response_model=NeedexResponse)
async def make_decision(
    view_id: str, request: DecisionRequest, principal: WorkspaceOwner
) -> NeedexResponse:
    await get_authorized_view(view_id, principal, require_approver=True, require_submission=True)
    await enforce_separation_of_duties(view_id, principal)
    try:
        return await decide(
            view_id,
            request,
            str(principal.user.email),
            store,
            principal.workspace_id,
        )
    except NeedexNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task View를 찾을 수 없습니다.") from exc
    except NeedexConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/taskviews/{view_id}/refine", response_model=NeedexResponse)
async def refine_view(
    view_id: str, request: RefineRequest, principal: BusinessPrincipal
) -> NeedexResponse:
    await get_authorized_view(view_id, principal, require_creator=True)
    try:
        return await refine(
            view_id,
            request,
            get_settings(),
            store,
            principal.workspace_id,
            str(principal.user.email),
        )
    except NeedexNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Task View를 찾을 수 없습니다.") from exc
    except NeedexConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="AI 계획 서비스에 연결하지 못했습니다."
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="AI 계획 결과가 유효하지 않습니다.") from exc


@app.get("/v1/taskviews/{view_id}/evidence", response_model=EvidenceContract)
async def get_evidence(view_id: str, principal: BusinessPrincipal) -> EvidenceContract:
    view = await get_authorized_view(view_id, principal)
    if not view.evidence:
        raise HTTPException(status_code=409, detail="승인 완료 후 Evidence Contract가 생성됩니다.")
    return view.evidence


@app.get("/v1/taskviews/{view_id}/compilation", response_model=CompilationResponse)
async def get_compilation(view_id: str, principal: BusinessPrincipal) -> CompilationResponse:
    view = await get_authorized_view(view_id, principal)
    return build_compilation(view)


@app.get("/v1/taskviews/{view_id}/discovery", response_model=DiscoveryResponse)
async def get_discovery(view_id: str, principal: BusinessPrincipal) -> DiscoveryResponse:
    view = await get_authorized_view(view_id, principal)
    return build_discovery(view)


@app.post("/v1/taskviews/{view_id}/submit", response_model=ApprovalSubmission)
async def submit_for_approval(view_id: str, principal: BusinessPrincipal) -> ApprovalSubmission:
    view = await get_authorized_view(view_id, principal, require_creator=True)
    if not is_approval_submission_allowed(view):
        raise HTTPException(
            status_code=409,
            detail="정책을 충족하거나 안전한 권장 대안이 있는 Task View만 제출할 수 있습니다.",
        )
    owners = [
        owner
        for key, owner in (("operations", "Tokyo Operations"), ("voc", "HCMC CS"))
        if key in view.plan.selected_sources
    ]
    if not owners:
        owners = ["Data Owner"]
    try:
        submission, replay = await store.submit_for_approval(
            view_id,
            workspace_id=principal.workspace_id,
            submitted_by=principal.user.id,
            actor_email=str(principal.user.email),
            assigned_owners=owners,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Task View를 찾을 수 없습니다.") from exc
    except SubmissionSnapshotConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail="기존 승인 요청의 제출 스냅샷과 현재 Task View가 일치하지 않습니다.",
        ) from exc
    position, total = await store.approval_queue_metrics(
        workspace_id=principal.workspace_id, view_id=view_id
    )
    state = "blocked" if view.status == "blocked" else "pending"
    return ApprovalSubmission(
        request_id=submission.request_id,
        view_id=view_id,
        state=state,
        queue_position=position or 1,
        queue_total=max(total, 1),
        assigned_owners=submission.assigned_owners,
        submitted_at=submission.submitted_at,
        idempotent_replay=replay,
    )


@app.get("/v1/taskviews/{view_id}/approval-status", response_model=ApprovalStatusResponse)
async def get_approval_status(view_id: str, principal: BusinessPrincipal) -> ApprovalStatusResponse:
    view = await get_authorized_view(view_id, principal)
    submission = await store.get_submission(view_id, workspace_id=principal.workspace_id)
    position, total = await store.approval_queue_metrics(
        workspace_id=principal.workspace_id, view_id=view_id
    )
    return build_approval_status(
        view,
        submission=submission,
        queue_total=total,
        queue_position=position,
    )


@app.get("/v1/taskviews/{view_id}/artifacts", response_model=NeedexArtifacts)
async def get_artifacts(view_id: str, principal: NeedexArtifactsPrincipal) -> NeedexArtifacts:
    view = await get_authorized_output_view(view_id, principal)
    enforce_api_key_output_mode(view, principal)
    enforce_output_availability(view)
    result = build_artifacts(view)
    await record_successful_api_key_use(principal)
    return result


@app.get("/v1/taskviews/{view_id}/data", response_model=DataResponse)
async def get_materialized_data(view_id: str, principal: NeedexDataPrincipal) -> DataResponse:
    view = await get_authorized_output_view(view_id, principal)
    enforce_api_key_output_mode(view, principal)
    enforce_output_availability(view)
    try:
        result = build_data_response(view)
    except NeedexExpiredError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await record_successful_api_key_use(principal)
    return result


@app.get("/v1/taskviews/{view_id}/data.csv")
async def download_materialized_data(
    view_id: str,
    principal: NeedexDataPrincipal,
    filter_field: str | None = Query(default=None, min_length=1, max_length=64),
    filter_value: str | None = Query(default=None, min_length=1, max_length=200),
) -> Response:
    if (filter_field is None) != (filter_value is None):
        raise HTTPException(status_code=400, detail="필터 항목과 필터 값을 함께 지정해야 합니다.")
    view = await get_authorized_output_view(view_id, principal)
    enforce_api_key_output_mode(view, principal)
    enforce_output_availability(view)
    try:
        result = build_data_response(view)
    except NeedexExpiredError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if filter_field is not None and filter_field not in result.columns:
        raise HTTPException(status_code=400, detail="다운로드 필터 항목이 결과에 없습니다.")
    export_source_rows = (
        await store.public_demo_export_rows(view.plan)
        if view.data_origin == "public_live"
        else result.rows
    )
    rows = [
        row
        for row in export_source_rows
        if filter_field is None or str(row.get(filter_field, "")) == filter_value
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=result.columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)

    actor_email = (
        None if isinstance(principal, WorkspaceApiKeyPrincipal) else str(principal.user.email)
    )
    await store.record_data_download(
        view_id=view_id,
        workspace_id=principal.workspace_id,
        actor_email=actor_email,
        row_count=len(rows),
        filter_field=filter_field,
        filter_value=filter_value,
    )
    await record_successful_api_key_use(principal)
    filename = f"needex-{view_id}.csv"
    return Response(
        content=output.getvalue().encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, private, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "X-Needex-Export-Mode": (
                "public-safe-records" if view.data_origin == "public_live" else "approved-view"
            ),
        },
    )


@app.get("/v1/taskviews/{view_id}/analytics", response_model=NeedexAnalytics)
async def get_task_view_analytics(
    view_id: str,
    principal: NeedexAnalyticsPrincipal,
    period_days: int = Query(default=7, ge=1, le=30),
    region: str = Query(default="JP", min_length=2, max_length=16),
    os: str = Query(default="iOS", min_length=2, max_length=24),
    cohort: str = Query(default="new", min_length=2, max_length=32),
) -> NeedexAnalytics:
    view = await get_authorized_output_view(view_id, principal)
    enforce_api_key_output_mode(view, principal)
    enforce_output_availability(view)
    try:
        result = build_analytics(
            view,
            period_days=period_days,
            region=region,
            os=os,
            cohort=cohort,
        )
    except NeedexExpiredError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await record_successful_api_key_use(principal)
    return result


@app.get("/v1/taskviews/{view_id}/audit-events", response_model=list[AuditEvent])
async def get_audit_events(view_id: str, principal: BusinessPrincipal) -> list[AuditEvent]:
    await get_authorized_view(view_id, principal)
    return await store.list_audit_events(view_id, workspace_id=principal.workspace_id)


@app.get("/v1/approval-requests", response_model=list[ApprovalReview])
async def list_approval_requests(
    principal: WorkspaceOwner,
) -> list[ApprovalReview]:
    views = await store.list_submitted_views_for_approver(
        user_id=principal.user.id,
        workspace_id=principal.workspace_id,
        limit=100,
    )
    return [build_approval_review(view, principal.user) for view in views]


@app.get("/v1/approval-requests/{view_id}", response_model=ApprovalReview)
async def get_approval_request(view_id: str, principal: WorkspaceOwner) -> ApprovalReview:
    try:
        view = await get_authorized_view(
            view_id, principal, require_approver=True, require_submission=True
        )
    except HTTPException as exc:
        raise HTTPException(status_code=404, detail="승인 요청을 찾을 수 없습니다.") from exc
    return build_approval_review(view, principal.user)


@app.post("/v1/approval-requests/{view_id}/decision", response_model=NeedexResponse)
async def decide_approval_request(
    view_id: str, request: ApprovalDecisionRequest, principal: WorkspaceOwner
) -> NeedexResponse:
    try:
        await get_authorized_view(
            view_id, principal, require_approver=True, require_submission=True
        )
    except HTTPException as exc:
        raise HTTPException(status_code=404, detail="승인 요청을 찾을 수 없습니다.") from exc
    await enforce_separation_of_duties(view_id, principal)
    try:
        if request.decision == "approve_recommended_alternative":
            return await approve_recommended_alternative(
                view_id,
                reason=request.reason,
                reviewer=str(principal.user.email),
                repository=store,
                workspace_id=principal.workspace_id,
            )
        return await decide(
            view_id,
            DecisionRequest(approved=request.decision == "approve", reason=request.reason),
            str(principal.user.email),
            store,
            principal.workspace_id,
        )
    except NeedexNotFoundError as exc:
        raise HTTPException(status_code=404, detail="승인 요청을 찾을 수 없습니다.") from exc
    except NeedexConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
