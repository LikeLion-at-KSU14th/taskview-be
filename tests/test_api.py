import asyncio
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from taskview_be.auth import password_hash
from taskview_be.config import get_settings
from taskview_be.mailer import DeliveryService, InMemoryMailer, TokenCipher
from taskview_be.main import app
from taskview_be.policy import evaluate_policy
from taskview_be.schemas import PreviewRequest, PurposeSpec, TransformPlanItem, ViewPlan
from taskview_be.store import store

TEST_PASSWORD = "Needex-Test!2026"
DELIVERY_KEY = Fernet.generate_key().decode()


async def cleanup_test_rows() -> None:
    connection = await asyncpg.connect(get_settings().taskview_database_url)
    try:
        async with connection.transaction():
            await connection.execute(
                """
                DELETE FROM task_views
                WHERE created_by IN (
                    SELECT id FROM users WHERE email LIKE '%@test.taskview.dev'
                )
                """
            )
            await connection.execute("DELETE FROM users WHERE email LIKE '%@test.taskview.dev'")
    finally:
        await connection.close()


@pytest.fixture(autouse=True)
def isolate_database_rows():
    asyncio.run(cleanup_test_rows())
    yield
    asyncio.run(cleanup_test_rows())


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}@test.taskview.dev"


def enable_fake_ai(monkeypatch) -> None:
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()


def signup(
    client: TestClient,
    email: str,
    *,
    verify: bool = True,
    onboard: bool = True,
    member_role: str = "requester",
) -> tuple[dict, dict[str, str]]:
    response = client.post(
        "/v1/auth/signup",
        json={"email": email, "display_name": "테스트 요청자", "password": TEST_PASSWORD},
    )
    assert response.status_code == 201
    payload = response.json()
    headers = {"authorization": f"Bearer {payload['session_token']}"}
    if verify:
        confirmed = client.post(
            "/v1/auth/email-verifications/confirm",
            json={"token": payload["verification_token"]},
        )
        assert confirmed.status_code == 200
        if onboard:
            complete_workspace_onboarding(client, headers, member_role=member_role)
    return payload, headers


def complete_workspace_onboarding(
    client: TestClient, headers: dict[str, str], *, member_role: str = "requester"
) -> dict:
    created = client.post(
        "/v1/workspaces",
        headers=headers,
        json={
            "name": f"Test Workspace {uuid4().hex[:8]}",
            "region": "KR-11",
            "default_ttl_days": 7,
            "member_role": member_role,
        },
    )
    assert created.status_code == 201
    workspace = created.json()
    completed = client.post(
        f"/v1/workspaces/{workspace['id']}/onboarding/complete",
        headers=headers,
        json={"skipped_invitations": True},
    )
    assert completed.status_code == 200
    return completed.json()


def grant_workspace_role(email: str, workspace_id: str, role: str) -> None:
    async def grant() -> None:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            await connection.execute(
                """
                INSERT INTO workspace_memberships (workspace_id, user_id, role)
                SELECT $1::uuid, id, $3
                FROM users
                WHERE LOWER(email) = LOWER($2)
                ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role
                """,
                workspace_id,
                email,
                role,
            )
            await connection.execute(
                """
                UPDATE users
                SET onboarding_status = 'complete'
                WHERE LOWER(email) = LOWER($1)
                """,
                email,
            )
        finally:
            await connection.close()

    asyncio.run(grant())


def latest_outbox_ciphertext(email: str, purpose: str) -> bytes:
    async def read() -> bytes:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            ciphertext = await connection.fetchval(
                """
                SELECT token_ciphertext
                FROM auth_delivery_outbox
                WHERE LOWER(recipient_email) = LOWER($1) AND purpose = $2
                ORDER BY created_at DESC
                LIMIT 1
                """,
                email,
                purpose,
            )
            assert ciphertext
            return bytes(ciphertext)
        finally:
            await connection.close()

    return asyncio.run(read())


def latest_outbox_token(email: str, purpose: str) -> str:
    return TokenCipher(DELIVERY_KEY).decrypt(latest_outbox_ciphertext(email, purpose))


def seed_privileged_user(role: str) -> tuple[str, str]:
    email = unique_email(role)

    async def seed() -> None:
        await store.start()
        try:
            await store.create_user(
                email=email,
                display_name=f"테스트 {role}",
                password_hash=password_hash.hash(TEST_PASSWORD),
                role="requester",
            )
        finally:
            await store.stop()

    asyncio.run(seed())
    return email, TEST_PASSWORD


def login(client: TestClient, email: str, user_password: str) -> tuple[dict, dict[str, str]]:
    response = client.post(
        "/v1/auth/login",
        json={"email": email, "password": user_password},
    )
    assert response.status_code == 200
    payload = response.json()
    return payload, {"authorization": f"Bearer {payload['session_token']}"}


def test_google_oauth_routes_are_not_exposed():
    with TestClient(app) as client:
        assert client.get("/v1/auth/oauth/google/start").status_code == 404
        assert (
            client.get(
                "/v1/auth/oauth/google/callback",
                params={"code": "test-code", "state": "test-state"},
            ).status_code
            == 404
        )


def create_preview(client: TestClient, headers: dict[str, str], ttl_days: int = 7) -> dict:
    response = client.post(
        "/v1/taskviews/preview",
        headers=headers,
        json={
            "purpose": "VOC를 지역과 이슈별로 묶어 다음 스프린트 우선순위를 정하고 싶다",
            "audience": "product",
            "ttl_days": ttl_days,
        },
    )
    assert response.status_code == 200
    return response.json()


def test_signup_me_duplicate_logout_and_revocation(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("requester")
    with TestClient(app) as client:
        session, headers = signup(client, email)
        assert session["user"]["role"] == "requester"

        me = client.get("/v1/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["email"] == email

        duplicate = client.post(
            "/v1/auth/signup",
            json={"email": email, "display_name": "중복 사용자", "password": TEST_PASSWORD},
        )
        assert duplicate.status_code == 409

        logout = client.post("/v1/auth/logout", headers=headers)
        assert logout.status_code == 204
        assert client.get("/v1/auth/me", headers=headers).status_code == 401

    get_settings.cache_clear()


def test_email_verification_and_password_reset_tokens_are_single_use(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("identity")

    with TestClient(app) as client:
        session, original_headers = signup(client, email, verify=False)
        assert session["user"]["email_verified"] is False
        assert session["next_path"] == "/verify-email"
        verification_token = session["verification_token"]
        assert verification_token
        assert client.get("/v1/data-sources", headers=original_headers).status_code == 403

        confirmed = client.post(
            "/v1/auth/email-verifications/confirm",
            json={"token": verification_token},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["verified"] is True
        assert confirmed.json()["onboarding_status"] == "workspace_setup"
        assert (
            client.post(
                "/v1/auth/email-verifications/confirm",
                json={"token": verification_token},
            ).status_code
            == 400
        )

        reset_request = client.post("/v1/auth/password-reset-requests", json={"email": email})
        assert reset_request.status_code == 202
        unknown_reset = client.post(
            "/v1/auth/password-reset-requests",
            json={"email": unique_email("unknown")},
        )
        assert unknown_reset.status_code == 202
        assert (
            reset_request.json()
            == unknown_reset.json()
            == {
                "accepted": True,
                "expires_at": None,
                "retry_after_seconds": 60,
                "development_token": None,
            }
        )
        reset_token = latest_outbox_token(email, "password_reset")
        reset = client.post(
            "/v1/auth/password-resets",
            json={"token": reset_token, "new_password": "ChangedPass2026"},
        )
        assert reset.status_code == 200
        assert client.get("/v1/auth/me", headers=original_headers).status_code == 401
        reset_headers = {"authorization": f"Bearer {reset.json()['session_token']}"}
        assert client.get("/v1/auth/me", headers=reset_headers).status_code == 200
        assert (
            client.post(
                "/v1/auth/password-resets",
                json={"token": reset_token, "new_password": "AnotherPass2026"},
            ).status_code
            == 400
        )

    get_settings.cache_clear()


def test_postgres_outbox_worker_clears_ciphertext_after_delivery(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("outbox-worker")
    with TestClient(app) as client:
        signup(client, email, verify=False)

    mailer = InMemoryMailer()

    async def drain_and_inspect() -> tuple[int, dict, bool]:
        await store.start()
        try:
            delivered = await DeliveryService(get_settings(), mailer=mailer).drain_once(store)
            pool = store._require_pool()
            async with pool.acquire() as connection:
                row = await connection.fetchrow(
                    """
                    SELECT token_ciphertext, delivered_at, attempts, last_error
                    FROM auth_delivery_outbox
                    WHERE recipient_email = $1 AND purpose = 'email_verification'
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    email,
                )
                plaintext_column_exists = await connection.fetchval(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'auth_delivery_outbox'
                          AND column_name = 'delivery_token'
                    )
                    """
                )
            assert row is not None
            return delivered, dict(row), plaintext_column_exists
        finally:
            await store.stop()

    delivered, outbox, plaintext_column_exists = asyncio.run(drain_and_inspect())
    assert delivered >= 1
    assert any(message.recipient == email for message in mailer.messages)
    assert outbox["token_ciphertext"] is None
    assert outbox["delivered_at"] is not None
    assert outbox["attempts"] == 0
    assert outbox["last_error"] is None
    assert plaintext_column_exists is False
    get_settings.cache_clear()


def test_delivery_misconfiguration_is_explicit_and_reset_response_does_not_enumerate(
    monkeypatch,
):
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "false")
    monkeypatch.delenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("TASKVIEW_SMTP_HOST", raising=False)
    get_settings.cache_clear()
    known_email, _ = seed_privileged_user("delivery-known")

    with TestClient(app) as client:
        readiness = client.get("/ready")
        assert readiness.status_code == 503
        signup_response = client.post(
            "/v1/auth/signup",
            json={
                "email": unique_email("delivery-blocked"),
                "display_name": "Blocked Delivery",
                "password": TEST_PASSWORD,
            },
        )
        assert signup_response.status_code == 503

        known = client.post("/v1/auth/password-reset-requests", json={"email": known_email})
        unknown = client.post(
            "/v1/auth/password-reset-requests",
            json={"email": unique_email("delivery-unknown")},
        )
        assert known.status_code == unknown.status_code == 503
        assert known.json() == unknown.json()

    get_settings.cache_clear()


def test_postgres_outbox_claim_is_exclusive_and_failure_uses_backoff(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("outbox-retry")
    with TestClient(app) as client:
        signup(client, email, verify=False)

    first_worker = str(uuid4())
    second_worker = str(uuid4())

    async def exercise_retry() -> tuple[dict, list[str], str]:
        await store.start()
        try:
            pool = store._require_pool()
            async with pool.acquire() as connection:
                delivery_id = await connection.fetchval(
                    """
                    UPDATE auth_delivery_outbox
                    SET next_attempt_at = '2000-01-01T00:00:00Z'
                    WHERE recipient_email = $1 AND purpose = 'email_verification'
                    RETURNING id
                    """,
                    email,
                )
            first_claim = await store.claim_outbox_deliveries(
                worker_id=first_worker,
                limit=1,
                max_attempts=6,
                claim_seconds=60,
            )
            assert [delivery.id for delivery in first_claim] == [str(delivery_id)]
            second_claim = await store.claim_outbox_deliveries(
                worker_id=second_worker,
                limit=100,
                max_attempts=6,
                claim_seconds=60,
            )
            await store.mark_outbox_failed(
                str(delivery_id),
                worker_id=first_worker,
                error="SMTP delivery failed",
                max_attempts=6,
            )
            async with pool.acquire() as connection:
                row = await connection.fetchrow(
                    """
                    SELECT attempts, next_attempt_at > CURRENT_TIMESTAMP AS backed_off,
                           last_error, token_ciphertext IS NOT NULL AS retry_payload_kept,
                           locked_at, lock_id, failed_at
                    FROM auth_delivery_outbox
                    WHERE id = $1
                    """,
                    delivery_id,
                )
            assert row is not None
            return dict(row), [delivery.id for delivery in second_claim], str(delivery_id)
        finally:
            await store.stop()

    retry, second_claim_ids, target_delivery_id = asyncio.run(exercise_retry())
    assert retry == {
        "attempts": 1,
        "backed_off": True,
        "last_error": "SMTP delivery failed",
        "retry_payload_kept": True,
        "locked_at": None,
        "lock_id": None,
        "failed_at": None,
    }
    assert target_delivery_id not in second_claim_ids
    get_settings.cache_clear()


def test_workspace_onboarding_and_batch_invites_persist(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("workspace")
    owner_invite_email = unique_email("invited-owner")
    security_invite_email = unique_email("invited-security")

    with TestClient(app) as client:
        session, headers = signup(client, email, verify=False)
        verified = client.post(
            "/v1/auth/email-verifications/confirm",
            json={"token": session["verification_token"]},
        )
        assert verified.status_code == 200

        created = client.post(
            "/v1/workspaces",
            headers=headers,
            json={
                "name": "Global Product Workspace",
                "region": "KR-11",
                "default_ttl_days": 7,
                "member_role": "admin",
            },
        )
        assert created.status_code == 201
        workspace = created.json()
        assert workspace["onboarding_complete"] is False
        assert workspace["member_role"] == "admin"
        assert client.get("/v1/auth/me", headers=headers).json()["role"] == "requester"

        invitations = client.post(
            f"/v1/workspaces/{workspace['id']}/invitations:batch",
            headers=headers,
            json={
                "invitations": [
                    {"email": owner_invite_email, "role": "data_owner"},
                    {"email": owner_invite_email, "role": "data_owner"},
                    {"email": security_invite_email, "role": "admin"},
                ]
            },
        )
        assert invitations.status_code == 200
        assert invitations.json()["invited_count"] == 2
        assert [item["status"] for item in invitations.json()["results"]] == [
            "invited",
            "duplicate",
            "invited",
        ]
        invitation_token = invitations.json()["results"][0]["development_token"]
        assert invitation_token
        assert invitations.json()["results"][1]["development_token"] is None
        invitation_ciphertext = latest_outbox_ciphertext(owner_invite_email, "workspace_invitation")
        assert invitation_token.encode() not in invitation_ciphertext
        assert TokenCipher(DELIVERY_KEY).decrypt(invitation_ciphertext) == invitation_token

        completed = client.post(
            f"/v1/workspaces/{workspace['id']}/onboarding/complete",
            headers=headers,
            json={"skipped_invitations": False},
        )
        assert completed.status_code == 200
        assert completed.json()["onboarding_complete"] is True
        assert client.get("/v1/auth/me", headers=headers).json()["onboarding_status"] == "complete"

        _, wrong_invitee_headers = signup(client, unique_email("wrong-invitee"), onboard=False)
        assert (
            client.post(
                "/v1/workspace-invitations/accept",
                headers=wrong_invitee_headers,
                json={"token": invitation_token},
            ).status_code
            == 403
        )
        _, invited_owner_headers = signup(client, owner_invite_email, onboard=False)
        accepted = client.post(
            "/v1/workspace-invitations/accept",
            headers=invited_owner_headers,
            json={"token": invitation_token},
        )
        assert accepted.status_code == 200
        assert accepted.json()["id"] == workspace["id"]
        assert accepted.json()["member_role"] == "data_owner"
        assert (
            client.post(
                "/v1/workspace-invitations/accept",
                headers=invited_owner_headers,
                json={"token": invitation_token},
            ).status_code
            == 400
        )

        updated = client.patch(
            "/v1/workspace/notifications",
            headers=headers,
            json={
                "approval_requested": True,
                "view_approved": True,
                "ttl_expiring": False,
                "audit_events": True,
            },
        )
        assert updated.status_code == 200
        assert updated.json()["notifications"]["ttl_expiring"] is False
        members = client.get("/v1/members", headers=headers)
        assert members.status_code == 200
        assert [member["email"] for member in members.json()] == [
            email,
            owner_invite_email,
        ]

        ui_workspace = client.get("/v1/ui/settings/workspace", headers=headers)
        assert ui_workspace.status_code == 200
        assert ui_workspace.json()["ttl"] == "7일"
        ui_workspace_update = client.patch(
            "/v1/ui/settings/workspace",
            headers=headers,
            json={
                "name": "Global Product Workspace",
                "region": "Seoul · KR",
                "ttl": "5일",
                "output": "Dashboard + API",
                "notifications": {
                    "approval": True,
                    "approved": True,
                    "expiry": True,
                    "audit": False,
                },
            },
        )
        assert ui_workspace_update.status_code == 200
        assert ui_workspace_update.json()["ttl"] == "5일"

        ui_team = client.get("/v1/ui/settings/team", headers=headers)
        assert ui_team.status_code == 200
        assert ui_team.json()[0]["role"] == "Security / Admin"
        ui_account = client.patch(
            "/v1/ui/account",
            headers=headers,
            json={"name": "김프로덕트", "email": email},
        )
        assert ui_account.status_code == 200
        assert ui_account.json()["name"] == "김프로덕트"

        sources = client.get("/v1/ui/data-sources", headers=headers)
        assert sources.status_code == 200
        assert sources.json()["stats"]["connected"] == 3
        assert len(sources.json()["sources"]) == 3
        source_detail = client.get("/v1/ui/data-sources/tokyo-operations", headers=headers)
        assert source_detail.status_code == 200
        assert source_detail.json()["owner"] == "NYC Open Data"
        connection_test = client.post(
            "/v1/ui/data-sources/test",
            headers=headers,
            json={
                "engine": "PostgreSQL",
                "name": "Tokyo Operations DB",
                "organization": "Operations · Tokyo · JP",
                "host": "postgres",
                "port": "5432",
                "database": "taskview",
                "username": "taskview",
                "password": "taskview",
                "tls": False,
            },
        )
        assert connection_test.status_code == 200
        assert connection_test.json()["read_only"] is True
        assert "password" not in connection_test.json()

    get_settings.cache_clear()


def test_session_and_view_persist_across_application_restart(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("persistent")
    with TestClient(app) as first_client:
        _, headers = signup(first_client, email)
        view = create_preview(first_client, headers)

    with TestClient(app) as restarted_client:
        assert restarted_client.get("/v1/auth/me", headers=headers).status_code == 200
        persisted = restarted_client.get(f"/v1/taskviews/{view['id']}", headers=headers)
        assert persisted.status_code == 200
        assert persisted.json()["created_by"] == view["created_by"]

    get_settings.cache_clear()


def test_requester_cannot_approve_but_owner_can(monkeypatch):
    enable_fake_ai(monkeypatch)
    owner_email, owner_password = seed_privileged_user("data_owner")
    with TestClient(app) as client:
        _, requester_headers = signup(client, unique_email("requester"))
        view = create_preview(client, requester_headers)
        workspace_id = client.get("/v1/workspace", headers=requester_headers).json()["id"]
        grant_workspace_role(owner_email, workspace_id, "data_owner")

        forbidden = client.post(
            f"/v1/taskviews/{view['id']}/decision",
            headers=requester_headers,
            json={"approved": True},
        )
        assert forbidden.status_code == 403

        submitted = client.post(f"/v1/taskviews/{view['id']}/submit", headers=requester_headers)
        assert submitted.status_code == 200

        owner, owner_headers = login(client, owner_email, owner_password)
        assert owner["user"]["role"] == "requester"
        approved = client.post(
            f"/v1/taskviews/{view['id']}/decision",
            headers=owner_headers,
            json={"approved": True, "reason": "최소화 범위 확인"},
        )
        assert approved.status_code == 200
        assert approved.json()["reviewed_by"] == owner_email

        evidence = client.get(f"/v1/taskviews/{view['id']}/evidence", headers=requester_headers)
        assert evidence.status_code == 200
        assert len(evidence.json()["content_sha256"]) == 64

        duplicate_decision = client.post(
            f"/v1/taskviews/{view['id']}/decision",
            headers=owner_headers,
            json={"approved": False},
        )
        assert duplicate_decision.status_code == 404

        immutable_evidence = client.post(
            f"/v1/taskviews/{view['id']}/refine",
            headers=requester_headers,
            json={"instruction": "승인된 내용을 다시 바꿔 주세요"},
        )
        assert immutable_evidence.status_code == 409

    get_settings.cache_clear()


def test_requester_cannot_read_another_users_view(monkeypatch):
    enable_fake_ai(monkeypatch)
    with TestClient(app) as client:
        _, first_headers = signup(client, unique_email("first"))
        _, second_headers = signup(client, unique_email("second"))
        view = create_preview(client, first_headers)

        hidden = client.get(f"/v1/taskviews/{view['id']}", headers=second_headers)
        assert hidden.status_code == 404

    get_settings.cache_clear()


def test_ttl_policy_blocks_owner_approval(monkeypatch):
    enable_fake_ai(monkeypatch)
    owner_email, owner_password = seed_privileged_user("data_owner")
    with TestClient(app) as client:
        _, requester_headers = signup(client, unique_email("ttl"))
        workspace_id = client.get("/v1/workspace", headers=requester_headers).json()["id"]
        grant_workspace_role(owner_email, workspace_id, "data_owner")
        _, owner_headers = login(client, owner_email, owner_password)
        view = create_preview(client, requester_headers, ttl_days=14)
        assert view["status"] == "blocked"
        compilation = client.get(
            f"/v1/taskviews/{view['id']}/compilation", headers=requester_headers
        )
        assert compilation.json()["can_submit_for_approval"] is True
        assert (
            client.post(f"/v1/taskviews/{view['id']}/submit", headers=requester_headers).status_code
            == 200
        )

        decision = client.post(
            f"/v1/taskviews/{view['id']}/decision",
            headers=owner_headers,
            json={"approved": True},
        )
        assert decision.status_code == 409

    get_settings.cache_clear()


def test_login_lockout(monkeypatch):
    enable_fake_ai(monkeypatch)
    email = unique_email("lockout")
    with TestClient(app) as client:
        signup(client, email)
        for _ in range(get_settings().taskview_login_max_failures):
            failed = client.post(
                "/v1/auth/login",
                json={"email": email, "password": "Wrong-Password!2026"},
            )
            assert failed.status_code == 401
        locked = client.post(
            "/v1/auth/login",
            json={"email": email, "password": TEST_PASSWORD},
        )
        assert locked.status_code == 429

    get_settings.cache_clear()


def test_policy_blocks_hallucinated_catalog_fields():
    request = PreviewRequest(
        purpose="VOC를 지역별로 묶어 다음 스프린트의 개선 우선순위를 결정하고 싶다",
        audience="product",
        ttl_days=7,
    )
    plan = ViewPlan(
        purpose_spec=PurposeSpec(
            objective=request.purpose,
            decision_to_support="우선순위 결정",
            audience="product",
            requested_fields=["invented_field"],
        ),
        selected_sources=["product"],
        transformations=[
            TransformPlanItem(
                source="voc",
                input_fields=["invented_field"],
                output_field="invented_summary",
                transformation="aggregate",
                rationale="모델이 임의로 제안한 필드",
            )
        ],
        preview_columns=["invented_preview"],
    )

    codes = {finding.code for finding in evaluate_policy(request, plan)}
    assert "SOURCE_NOT_SELECTED" in codes
    assert "UNKNOWN_CATALOG_FIELD" in codes
    assert "UNKNOWN_PREVIEW_COLUMN" in codes
