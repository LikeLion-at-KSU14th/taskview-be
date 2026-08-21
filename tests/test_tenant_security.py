import asyncio
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from taskview_be.config import get_settings
from taskview_be.main import app
from taskview_be.store import store

TEST_PASSWORD = "Needex-Test!2026"
TEST_DOMAIN = "tenant-security.taskview.dev"
DELIVERY_KEY = Fernet.generate_key().decode()


async def cleanup_test_rows() -> None:
    connection = await asyncpg.connect(get_settings().taskview_database_url)
    try:
        async with connection.transaction():
            await connection.execute(
                """
                DELETE FROM task_views
                WHERE created_by IN (
                    SELECT id FROM users WHERE email LIKE $1
                )
                """,
                f"%@{TEST_DOMAIN}",
            )
            await connection.execute("DELETE FROM users WHERE email LIKE $1", f"%@{TEST_DOMAIN}")
    finally:
        await connection.close()


@pytest.fixture(autouse=True)
def isolate_database_rows():
    asyncio.run(cleanup_test_rows())
    yield
    asyncio.run(cleanup_test_rows())


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}@{TEST_DOMAIN}"


def headers(session: dict) -> dict[str, str]:
    return {"authorization": f"Bearer {session['session_token']}"}


def signup_verified(client: TestClient, prefix: str) -> tuple[dict, dict[str, str]]:
    response = client.post(
        "/v1/auth/signup",
        json={
            "email": unique_email(prefix),
            "display_name": f"{prefix} user",
            "password": TEST_PASSWORD,
        },
    )
    assert response.status_code == 201
    session = response.json()
    auth_headers = headers(session)
    assert (
        client.post(
            "/v1/auth/email-verifications/confirm",
            json={"token": session["verification_token"]},
        ).status_code
        == 200
    )
    return session, auth_headers


def create_workspace(
    client: TestClient,
    auth_headers: dict[str, str],
    prefix: str,
    *,
    role: str = "requester",
    complete: bool = True,
) -> dict:
    response = client.post(
        "/v1/workspaces",
        headers=auth_headers,
        json={
            "name": f"{prefix} Workspace",
            "region": "KR-11",
            "default_ttl_days": 7,
            "member_role": role,
        },
    )
    assert response.status_code == 201
    workspace = response.json()
    if complete:
        completed = client.post(
            f"/v1/workspaces/{workspace['id']}/onboarding/complete",
            headers=auth_headers,
            json={"skipped_invitations": True},
        )
        assert completed.status_code == 200
    return workspace


def grant_membership(
    email: str, workspace_id: str, role: str, *, global_role: str = "requester"
) -> None:
    async def grant() -> None:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            async with connection.transaction():
                await connection.execute(
                    """
                    INSERT INTO workspace_memberships (workspace_id, user_id, role)
                    SELECT $1::uuid, id, $3
                    FROM users
                    WHERE LOWER(email) = LOWER($2)
                    ON CONFLICT (workspace_id, user_id)
                    DO UPDATE SET role = EXCLUDED.role, joined_at = CURRENT_TIMESTAMP
                    """,
                    workspace_id,
                    email,
                    role,
                )
                await connection.execute(
                    """
                    UPDATE users
                    SET onboarding_status = 'complete', role = $2
                    WHERE LOWER(email) = LOWER($1)
                    """,
                    email,
                    global_role,
                )
        finally:
            await connection.close()

    asyncio.run(grant())


def create_view(client: TestClient, auth_headers: dict[str, str], *, ttl_days: int = 7) -> dict:
    response = client.post(
        "/v1/taskviews/preview",
        headers=auth_headers,
        json={
            "purpose": "고객 문의를 지역과 원인별로 집계해 제품 우선순위를 결정하고 싶다",
            "audience": "product",
            "ttl_days": ttl_days,
        },
    )
    assert response.status_code == 200
    return response.json()


def test_business_api_requires_completed_onboarding_and_active_membership(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()

    with TestClient(app) as client:
        _, requester = signup_verified(client, "onboarding")
        assert client.get("/v1/data-sources", headers=requester).status_code == 409

        workspace = create_workspace(client, requester, "Incomplete", complete=False)
        assert client.get("/v1/data-sources", headers=requester).status_code == 409

        assert (
            client.post(
                f"/v1/workspaces/{workspace['id']}/onboarding/complete",
                headers=requester,
                json={"skipped_invitations": True},
            ).status_code
            == 200
        )
        assert client.get("/v1/data-sources", headers=requester).status_code == 200

    get_settings.cache_clear()


def test_cross_tenant_views_and_approvals_are_isolated(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()

    with TestClient(app) as client:
        requester_a_session, requester_a = signup_verified(client, "requester-a")
        workspace_a = create_workspace(client, requester_a, "Tenant A")
        requester_b_session, requester_b = signup_verified(client, "requester-b")
        workspace_b = create_workspace(client, requester_b, "Tenant B")

        owner_a_session, owner_a = signup_verified(client, "owner-a")
        owner_b_session, owner_b = signup_verified(client, "owner-b")
        grant_membership(owner_a_session["user"]["email"], workspace_a["id"], "data_owner")
        grant_membership(
            owner_b_session["user"]["email"],
            workspace_b["id"],
            "data_owner",
            global_role="admin",
        )

        view_a = create_view(client, requester_a)
        unsubmitted_a = create_view(client, requester_a)
        assert (
            client.post(f"/v1/taskviews/{view_a['id']}/submit", headers=requester_a).status_code
            == 200
        )

        assert client.get(f"/v1/taskviews/{view_a['id']}", headers=requester_b).status_code == 404
        assert client.get(f"/v1/taskviews/{view_a['id']}", headers=owner_b).status_code == 404
        assert (
            client.get(f"/v1/approval-requests/{view_a['id']}", headers=owner_b).status_code == 404
        )
        assert (
            client.post(
                f"/v1/approval-requests/{view_a['id']}/decision",
                headers=owner_b,
                json={"decision": "approve", "reason": "cross tenant"},
            ).status_code
            == 404
        )

        approval_ids = {
            item["view_id"] for item in client.get("/v1/approval-requests", headers=owner_a).json()
        }
        assert view_a["id"] in approval_ids
        assert unsubmitted_a["id"] not in approval_ids
        assert (
            client.get(f"/v1/approval-requests/{unsubmitted_a['id']}", headers=owner_a).status_code
            == 404
        )

        approved = client.post(
            f"/v1/approval-requests/{view_a['id']}/decision",
            headers=owner_a,
            json={"decision": "approve", "reason": "tenant-local approval"},
        )
        assert approved.status_code == 200
        assert approved.json()["revision"] == view_a["revision"] + 1

        assert requester_a_session["user"]["role"] == "requester"
        assert requester_b_session["user"]["role"] == "requester"

    get_settings.cache_clear()


def test_submission_snapshot_blocks_refine_tampering_and_self_approval(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()

    with TestClient(app) as client:
        _, admin_headers = signup_verified(client, "admin")
        create_workspace(client, admin_headers, "Admin", role="admin")
        view = create_view(client, admin_headers)
        assert (
            client.post(f"/v1/taskviews/{view['id']}/submit", headers=admin_headers).status_code
            == 200
        )

        blocked_refine = client.post(
            f"/v1/taskviews/{view['id']}/refine",
            headers=admin_headers,
            json={"instruction": "제출 후 원본 목적을 바꿔 주세요"},
        )
        assert blocked_refine.status_code == 409
        self_approval = client.post(
            f"/v1/approval-requests/{view['id']}/decision",
            headers=admin_headers,
            json={"decision": "approve", "reason": "self approval"},
        )
        assert self_approval.status_code == 403

    get_settings.cache_clear()


def test_submission_hash_and_revision_cas_reject_stale_state(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()

    with TestClient(app) as client:
        _, requester = signup_verified(client, "snapshot-requester")
        workspace = create_workspace(client, requester, "Snapshot")
        owner_session, owner = signup_verified(client, "snapshot-owner")
        grant_membership(owner_session["user"]["email"], workspace["id"], "data_owner")
        view = create_view(client, requester)
        assert (
            client.post(f"/v1/taskviews/{view['id']}/submit", headers=requester).status_code == 200
        )

        async def tamper_payload_without_revision() -> None:
            connection = await asyncpg.connect(get_settings().taskview_database_url)
            try:
                await connection.execute(
                    """
                    UPDATE task_views
                    SET payload = jsonb_set(payload, '{purpose}', '"tampered"'::jsonb)
                    WHERE id = $1
                    """,
                    view["id"],
                )
            finally:
                await connection.close()

        asyncio.run(tamper_payload_without_revision())
        assert (
            client.post(
                f"/v1/approval-requests/{view['id']}/decision",
                headers=owner,
                json={"decision": "approve", "reason": "stale snapshot"},
            ).status_code
            == 409
        )

        cas_view = create_view(client, requester)

    async def race_revision() -> tuple[bool, bool]:
        await store.start()
        try:
            first = await store.get(cas_view["id"], workspace_id=workspace["id"])
            second = await store.get(cas_view["id"], workspace_id=workspace["id"])
            assert first is not None and second is not None
            expected_revision = first.revision
            first.purpose += " first"
            second.purpose += " second"
            first_result, second_result = await asyncio.gather(
                store.save_if_revision(
                    first,
                    workspace_id=workspace["id"],
                    expected_revision=expected_revision,
                    expected_status=first.status,
                ),
                store.save_if_revision(
                    second,
                    workspace_id=workspace["id"],
                    expected_revision=expected_revision,
                    expected_status=second.status,
                ),
            )
            return first_result, second_result
        finally:
            await store.stop()

    assert sorted(asyncio.run(race_revision())) == [False, True]
    get_settings.cache_clear()


def test_requester_cannot_escalate_workspace_or_admin_integrations(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()

    with TestClient(app) as client:
        _, requester = signup_verified(client, "least-privilege")
        workspace = create_workspace(client, requester, "Least Privilege")

        assert (
            client.patch("/v1/workspace", headers=requester, json={"name": "Escalated"}).status_code
            == 403
        )
        assert (
            client.patch(
                "/v1/workspace/notifications",
                headers=requester,
                json={"audit_events": True},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/v1/ui/settings/team",
                headers=requester,
                json={"email": unique_email("target"), "role": "Security / Admin"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/v1/ui/data-sources/scan",
                headers=requester,
                json={
                    "engine": "PostgreSQL",
                    "name": "Unsafe",
                    "organization": "Tenant",
                    "host": "db.internal",
                    "port": "5432",
                    "database": "tenant",
                    "username": "reader",
                    "password": "not-returned",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/v1/ui/data-sources/test",
                headers=requester,
                json={
                    "engine": "PostgreSQL",
                    "name": "Unsafe",
                    "organization": "Tenant",
                    "host": "db.internal",
                    "port": "5432",
                    "database": "tenant",
                    "username": "reader",
                    "password": "not-returned",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/v1/ui/data-sources/scan/complete",
                headers=requester,
                json={"owner": "Product", "region": "KR", "policy": "default"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/v1/workspaces/{workspace['id']}/invitations:batch",
                headers=requester,
                json={
                    "invitations": [
                        {
                            "email": unique_email("late-admin"),
                            "role": "admin",
                        }
                    ]
                },
            ).status_code
            == 404
        )

    get_settings.cache_clear()


def test_tenant_schema_migration_is_idempotent_and_enforces_scope(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    get_settings.cache_clear()

    with TestClient(app):
        pass
    with TestClient(app):
        pass

    async def inspect_schema() -> tuple[dict[str, str], dict[str, str]]:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            task_view_columns = await connection.fetch(
                """
                SELECT column_name, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'task_views'
                  AND column_name IN ('workspace_id', 'revision', 'content_hash')
                """
            )
            submission_columns = await connection.fetch(
                """
                SELECT column_name, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'task_view_submissions'
                  AND column_name IN (
                      'workspace_id', 'submitted_revision', 'submitted_content_hash'
                  )
                """
            )
            return (
                {row["column_name"]: row["is_nullable"] for row in task_view_columns},
                {row["column_name"]: row["is_nullable"] for row in submission_columns},
            )
        finally:
            await connection.close()

    task_views, submissions = asyncio.run(inspect_schema())
    assert task_views == {
        "workspace_id": "NO",
        "revision": "NO",
        "content_hash": "NO",
    }
    assert submissions["workspace_id"] == "NO"
    assert submissions["submitted_revision"] == "YES"
    assert submissions["submitted_content_hash"] == "YES"
    get_settings.cache_clear()
