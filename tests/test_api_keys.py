import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from taskview_be.auth import hash_session_token
from taskview_be.config import get_settings
from taskview_be.main import app

TEST_PASSWORD = "Needex-Test!2026"
TEST_DOMAIN = "api-keys.taskview.dev"
DELIVERY_KEY = Fernet.generate_key().decode()
ALL_SCOPES = {
    "taskviews:artifacts:read",
    "taskviews:data:read",
    "taskviews:analytics:read",
}


async def cleanup_test_rows() -> None:
    connection = await asyncpg.connect(get_settings().taskview_database_url)
    try:
        async with connection.transaction():
            await connection.execute(
                """
                DELETE FROM workspaces
                WHERE id IN (
                    SELECT membership.workspace_id
                    FROM workspace_memberships membership
                    JOIN users user_account ON user_account.id = membership.user_id
                    WHERE user_account.email LIKE $1
                )
                """,
                f"%@{TEST_DOMAIN}",
            )
            await connection.execute("DELETE FROM users WHERE email LIKE $1", f"%@{TEST_DOMAIN}")
    finally:
        await connection.close()


@pytest.fixture(autouse=True)
def isolate_database_rows(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    monkeypatch.setenv("TASKVIEW_MAIL_WORKER_ENABLED", "false")
    get_settings.cache_clear()
    asyncio.run(cleanup_test_rows())
    yield
    asyncio.run(cleanup_test_rows())
    get_settings.cache_clear()


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}@{TEST_DOMAIN}"


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


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
    assert session["verification_token"]
    confirmed = client.post(
        "/v1/auth/email-verifications/confirm",
        json={"token": session["verification_token"]},
    )
    assert confirmed.status_code == 200
    return session, bearer(session["session_token"])


def create_workspace(
    client: TestClient,
    headers: dict[str, str],
    prefix: str,
    *,
    member_role: str = "admin",
) -> dict:
    created = client.post(
        "/v1/workspaces",
        headers=headers,
        json={
            "name": f"{prefix} Workspace",
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
    return workspace


def grant_membership(email: str, workspace_id: str, role: str) -> None:
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
                    SET onboarding_status = 'complete'
                    WHERE LOWER(email) = LOWER($1)
                    """,
                    email,
                )
        finally:
            await connection.close()

    asyncio.run(grant())


def create_team(client: TestClient, prefix: str = "primary") -> dict:
    admin_session, admin = signup_verified(client, f"{prefix}-admin")
    workspace = create_workspace(client, admin, prefix)
    requester_session, requester = signup_verified(client, f"{prefix}-requester")
    owner_session, owner = signup_verified(client, f"{prefix}-owner")
    grant_membership(requester_session["user"]["email"], workspace["id"], "requester")
    grant_membership(owner_session["user"]["email"], workspace["id"], "data_owner")
    return {
        "workspace": workspace,
        "admin_session": admin_session,
        "admin": admin,
        "requester_session": requester_session,
        "requester": requester,
        "owner_session": owner_session,
        "owner": owner,
    }


def create_view(
    client: TestClient,
    headers: dict[str, str],
    *,
    output_mode: str = "dashboard_api",
) -> dict:
    response = client.post(
        "/v1/taskviews/preview",
        headers=headers,
        json={
            "purpose": "고객 문의를 지역과 원인별로 집계해 제품 우선순위를 결정한다",
            "audience": "product",
            "ttl_days": 7,
            "region": "KR",
            "output_mode": output_mode,
        },
    )
    assert response.status_code == 200
    return response.json()


def approve_view(client: TestClient, team: dict, *, output_mode: str = "dashboard_api") -> dict:
    view = create_view(client, team["requester"], output_mode=output_mode)
    submitted = client.post(f"/v1/taskviews/{view['id']}/submit", headers=team["requester"])
    assert submitted.status_code == 200
    approved = client.post(
        f"/v1/approval-requests/{view['id']}/decision",
        headers=team["owner"],
        json={"decision": "approve", "reason": "목적과 최소화 범위를 확인했습니다."},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    return approved.json()


def create_key(
    client: TestClient,
    admin_headers: dict[str, str],
    *,
    scopes: list[str] | None = None,
    name: str = "Production Key",
) -> dict:
    payload = {"name": name}
    if scopes is not None:
        payload["scopes"] = scopes
    response = client.post(
        "/v1/ui/settings/integrations/keys",
        headers=admin_headers,
        json=payload,
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def fetch_key_row(key_id: str) -> asyncpg.Record:
    async def fetch() -> asyncpg.Record:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            row = await connection.fetchrow(
                """
                SELECT secret_hash, key_prefix, scopes, created_at, expires_at,
                       last_used_at, revoked_at, row_to_json(workspace_api_keys)::text AS serialized
                FROM workspace_api_keys
                WHERE id = $1::uuid
                """,
                key_id,
            )
            assert row is not None
            return row
        finally:
            await connection.close()

    return asyncio.run(fetch())


def update_database(statement: str, *values: object) -> None:
    async def update() -> None:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            await connection.execute(statement, *values)
        finally:
            await connection.close()

    asyncio.run(update())


def test_key_creation_is_admin_only_hashed_and_secret_is_one_time():
    with TestClient(app) as client:
        team = create_team(client)

        for forbidden in (team["requester"], team["owner"]):
            response = client.post(
                "/v1/ui/settings/integrations/keys",
                headers=forbidden,
                json={"name": "Forbidden Key"},
            )
            assert response.status_code == 403

        key = create_key(client, team["admin"])
        secret = key["secret"]
        assert secret.startswith("tv_live_")
        assert set(key["scopes"]) == ALL_SCOPES
        assert key["status"] == "active"
        expires_at = datetime.fromisoformat(key["expiresAt"])
        assert timedelta(days=89, hours=23) < expires_at - datetime.now(UTC) <= timedelta(days=90)

        row = fetch_key_row(key["id"])
        assert row["secret_hash"] == hash_session_token(secret)
        assert row["secret_hash"] != secret
        assert row["key_prefix"] == secret[:16]
        assert secret not in row["serialized"]
        assert set(row["scopes"]) == ALL_SCOPES

        listed = client.get("/v1/ui/settings/integrations/keys", headers=team["admin"])
        assert listed.status_code == 200
        assert listed.headers["cache-control"] == "no-store"
        assert listed.json()[0]["id"] == key["id"]
        assert "secret" not in listed.json()[0]

        settings = client.get("/v1/ui/settings/integrations", headers=team["admin"])
        assert settings.status_code == 200
        assert settings.headers["cache-control"] == "no-store"
        assert settings.json()["webhooks"] == []
        assert secret not in settings.text


def test_scopes_gate_outputs_and_only_success_updates_last_used():
    with TestClient(app) as client:
        team = create_team(client)
        view = approve_view(client, team)
        key = create_key(
            client,
            team["admin"],
            scopes=["taskviews:data:read"],
            name="Data only",
        )
        api_headers = bearer(key["secret"])

        assert fetch_key_row(key["id"])["last_used_at"] is None
        assert (
            client.get(f"/v1/taskviews/{view['id']}/artifacts", headers=api_headers).status_code
            == 403
        )
        assert (
            client.get(f"/v1/taskviews/{view['id']}/analytics", headers=api_headers).status_code
            == 403
        )
        assert fetch_key_row(key["id"])["last_used_at"] is None

        data = client.get(f"/v1/taskviews/{view['id']}/data", headers=api_headers)
        assert data.status_code == 200
        assert data.json()["data_origin"] == "synthetic_demo"
        assert fetch_key_row(key["id"])["last_used_at"] is not None

        full_key = create_key(client, team["admin"], name="All outputs")
        full_headers = bearer(full_key["secret"])
        for suffix in ("artifacts", "data", "analytics"):
            assert (
                client.get(f"/v1/taskviews/{view['id']}/{suffix}", headers=full_headers).status_code
                == 200
            )


def test_workspace_output_state_ttl_expiry_and_revoke_boundaries():
    with TestClient(app) as client:
        team = create_team(client)
        approved = approve_view(client, team)
        dashboard_only = approve_view(client, team, output_mode="dashboard")
        unapproved = create_view(client, team["requester"])
        other_team = create_team(client, "other")
        other_view = create_view(client, other_team["requester"])
        key = create_key(client, team["admin"])
        api_headers = bearer(key["secret"])

        assert (
            client.get(f"/v1/taskviews/{other_view['id']}/data", headers=api_headers).status_code
            == 404
        )
        assert fetch_key_row(key["id"])["last_used_at"] is None

        for suffix in ("artifacts", "data", "analytics"):
            assert (
                client.get(
                    f"/v1/taskviews/{dashboard_only['id']}/{suffix}", headers=api_headers
                ).status_code
                == 403
            )
            assert (
                client.get(
                    f"/v1/taskviews/{unapproved['id']}/{suffix}", headers=api_headers
                ).status_code
                == 409
            )
        assert fetch_key_row(key["id"])["last_used_at"] is None

        update_database(
            """
            UPDATE task_views
            SET payload = jsonb_set(
                payload, '{evidence,expires_at}', '"2000-01-01T00:00:00Z"'::jsonb
            )
            WHERE id = $1
            """,
            approved["id"],
        )
        for suffix in ("artifacts", "data", "analytics"):
            session_response = client.get(
                f"/v1/taskviews/{approved['id']}/{suffix}", headers=team["requester"]
            )
            key_response = client.get(
                f"/v1/taskviews/{approved['id']}/{suffix}", headers=api_headers
            )
            assert session_response.status_code == 410
            assert key_response.status_code == 410
        assert fetch_key_row(key["id"])["last_used_at"] is None

        revoked = client.delete(
            f"/v1/ui/settings/integrations/keys/{key['id']}", headers=team["admin"]
        )
        assert revoked.status_code == 204
        assert revoked.headers["cache-control"] == "no-store"
        assert (
            client.get(f"/v1/taskviews/{approved['id']}/data", headers=api_headers).status_code
            == 401
        )

        expiring_key = create_key(client, team["admin"], name="Expiring key")
        update_database(
            "UPDATE workspace_api_keys SET expires_at = CURRENT_TIMESTAMP WHERE id = $1::uuid",
            expiring_key["id"],
        )
        assert (
            client.get(
                f"/v1/taskviews/{approved['id']}/data", headers=bearer(expiring_key["secret"])
            ).status_code
            == 401
        )
        assert (
            client.get(
                f"/v1/taskviews/{approved['id']}/data",
                headers=bearer("tv_live_" + "x" * 43),
            ).status_code
            == 401
        )


def test_api_key_cannot_fall_back_to_session_and_evidence_lookup_is_exact():
    with TestClient(app) as client:
        team = create_team(client)
        first = approve_view(client, team)
        second = approve_view(client, team)
        other_team = create_team(client, "evidence-other")
        other = approve_view(client, other_team)
        key = create_key(client, team["admin"])
        api_headers = bearer(key["secret"])

        blocked_requests = [
            ("get", "/v1/taskviews", None),
            ("get", "/v1/ui/settings/integrations", None),
            ("post", f"/v1/taskviews/{first['id']}/submit", None),
            ("get", "/v1/approval-requests", None),
            (
                "post",
                f"/v1/approval-requests/{first['id']}/decision",
                {"decision": "approve", "reason": "API key must not approve"},
            ),
        ]
        for method, path, payload in blocked_requests:
            response = client.request(method, path, headers=api_headers, json=payload)
            assert response.status_code == 401
        assert fetch_key_row(key["id"])["last_used_at"] is None

        assert client.get("/v1/taskviews", headers=team["requester"]).status_code == 200
        assert (
            client.get(f"/v1/taskviews/{first['id']}/data", headers=team["requester"]).status_code
            == 200
        )

        exact = client.get(
            f"/v1/ui/evidence-contracts/{second['evidence']['view_id']}",
            headers=team["requester"],
        )
        assert exact.status_code == 200
        assert exact.json()["id"] == second["evidence"]["view_id"]
        assert exact.json()["id"] != first["evidence"]["view_id"]
        assert (
            client.get(
                "/v1/ui/evidence-contracts/tv_missing_evidence",
                headers=team["requester"],
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/v1/ui/evidence-contracts/{other['evidence']['view_id']}",
                headers=team["requester"],
            ).status_code
            == 404
        )
