import asyncio
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from taskview_be.auth import password_hash
from taskview_be.config import get_settings
from taskview_be.main import app
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
                    SELECT id FROM users WHERE email LIKE '%@experience.taskview.dev'
                )
                """
            )
            await connection.execute(
                "DELETE FROM users WHERE email LIKE '%@experience.taskview.dev'"
            )
    finally:
        await connection.close()


@pytest.fixture(autouse=True)
def isolate_database_rows():
    asyncio.run(cleanup_test_rows())
    yield
    asyncio.run(cleanup_test_rows())


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}@experience.taskview.dev"


def signup(client: TestClient, prefix: str) -> tuple[dict, dict[str, str]]:
    response = client.post(
        "/v1/auth/signup",
        json={
            "email": unique_email(prefix),
            "display_name": "Product Team",
            "password": TEST_PASSWORD,
        },
    )
    assert response.status_code == 201
    payload = response.json()
    headers = {"authorization": f"Bearer {payload['session_token']}"}
    confirmed = client.post(
        "/v1/auth/email-verifications/confirm",
        json={"token": payload["verification_token"]},
    )
    assert confirmed.status_code == 200
    created = client.post(
        "/v1/workspaces",
        headers=headers,
        json={
            "name": f"Experience {uuid4().hex[:8]}",
            "region": "KR-11",
            "default_ttl_days": 7,
            "member_role": "requester",
        },
    )
    assert created.status_code == 201
    completed = client.post(
        f"/v1/workspaces/{created.json()['id']}/onboarding/complete",
        headers=headers,
        json={"skipped_invitations": True},
    )
    assert completed.status_code == 200
    return payload, headers


def grant_workspace_role(email: str, workspace_id: str, role: str) -> None:
    async def grant() -> None:
        connection = await asyncpg.connect(get_settings().taskview_database_url)
        try:
            await connection.execute(
                """
                INSERT INTO workspace_memberships (workspace_id, user_id, role)
                SELECT $1::uuid, id, $3 FROM users WHERE LOWER(email) = LOWER($2)
                ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role
                """,
                workspace_id,
                email,
                role,
            )
            await connection.execute(
                "UPDATE users SET onboarding_status = 'complete' WHERE LOWER(email) = LOWER($1)",
                email,
            )
        finally:
            await connection.close()

    asyncio.run(grant())


def seed_owner() -> tuple[str, str]:
    email = unique_email("owner")

    async def seed() -> None:
        await store.start()
        try:
            await store.create_user(
                email=email,
                display_name="Tokyo Operations",
                password_hash=password_hash.hash(TEST_PASSWORD),
                role="requester",
            )
        finally:
            await store.stop()

    asyncio.run(seed())
    return email, TEST_PASSWORD


def test_page_contracts_and_safe_alternative_flow(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()
    owner_email, owner_password = seed_owner()

    with TestClient(app) as client:
        assert client.get("/v1/data-sources").status_code == 401
        _, requester_headers = signup(client, "requester")
        workspace_id = client.get("/v1/workspace", headers=requester_headers).json()["id"]
        grant_workspace_role(owner_email, workspace_id, "data_owner")

        sources = client.get("/v1/data-sources", headers=requester_headers)
        assert sources.status_code == 200
        assert [source["key"] for source in sources.json()] == [
            "product",
            "operations",
            "voc",
        ]

        interpretation = client.post(
            "/v1/purpose/interpret",
            headers=requester_headers,
            json={
                "purpose": "일본 iOS 신규 사용자의 최근 회원가입 이탈 원인을 찾고 싶습니다.",
                "region": "JP",
                "ttl_days": 14,
                "output_mode": "dashboard_api",
            },
        )
        assert interpretation.status_code == 200
        assert interpretation.json()["task"] == "JP signup dropoff diagnosis"
        assert len(interpretation.json()["matched_sources"]) == 3
        rejected_extra_property = client.post(
            "/v1/purpose/interpret",
            headers=requester_headers,
            json={
                "purpose": "일본 iOS 신규 사용자의 최근 회원가입 이탈 원인을 찾고 싶습니다.",
                "region": "JP",
                "internal_role": "admin",
            },
        )
        assert rejected_extra_property.status_code == 422

        compiled_view = client.post(
            "/v1/taskviews/preview",
            headers=requester_headers,
            json={
                "purpose": "일본 iOS 신규 사용자의 최근 회원가입 이탈 원인을 찾고 싶습니다.",
                "audience": "product",
                "ttl_days": 14,
                "region": "JP",
                "output_mode": "dashboard_api",
            },
        )
        assert compiled_view.status_code == 200
        view = compiled_view.json()
        assert view["status"] == "blocked"
        assert view["region"] == "JP"

        compilation = client.get(
            f"/v1/taskviews/{view['id']}/compilation", headers=requester_headers
        )
        assert compilation.status_code == 200
        assert compilation.json()["stage"] == "blocked"
        assert compilation.json()["source_match_count"] == 3
        assert compilation.json()["can_submit_for_approval"] is True
        assert any(
            check["code"] == "TTL_LIMIT" and check["result"] == "DENY"
            for check in compilation.json()["firewall_checks"]
        )

        assert client.get("/v1/approval-requests", headers=requester_headers).status_code == 403
        assert (
            client.get(f"/v1/taskviews/{view['id']}/data", headers=requester_headers).status_code
            == 409
        )
        submitted = client.post(f"/v1/taskviews/{view['id']}/submit", headers=requester_headers)
        assert submitted.status_code == 200

        owner_login = client.post(
            "/v1/auth/login",
            json={"email": owner_email, "password": owner_password},
        )
        assert owner_login.status_code == 200
        owner = {"authorization": f"Bearer {owner_login.json()['session_token']}"}
        review = client.get(f"/v1/approval-requests/{view['id']}", headers=owner)
        assert review.status_code == 200
        assert review.json()["risk_level"] == "high"
        assert review.json()["recommended_alternative"]["available"] is True
        assert review.json()["recommended_alternative"]["changes"] == [
            {
                "before": "TTL 14 days",
                "after": "TTL 7 days",
                "operator": "TTL",
            }
        ]

        approved = client.post(
            f"/v1/approval-requests/{view['id']}/decision",
            headers=owner,
            json={
                "decision": "approve_recommended_alternative",
                "reason": "TTL을 정책 범위로 낮춘 안전한 대안 승인",
            },
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"
        assert approved.json()["ttl_days"] == 7
        assert approved.json()["evidence"]["policy_version"].endswith("2026-08-18")

        artifacts = client.get(f"/v1/taskviews/{view['id']}/artifacts", headers=requester_headers)
        assert artifacts.status_code == 200
        artifact = artifacts.json()
        assert artifact["api"]["path"].endswith(f"/{view['id']}/data")
        assert [item["source_name"] for item in artifact["source_lineage"]] == [
            "FCC Complaints",
            "NYC 311",
            "NHTSA Safety",
        ]
        assert {
            "customer_name",
            "phone",
            "email",
            "exact_address",
            "birth_date",
            "ticket_text",
            "error_log",
        }.issubset(artifact["removed_fields"])
        assert "status = 'approved'" in artifact["sql"]

        data = client.get(f"/v1/taskviews/{view['id']}/data", headers=requester_headers)
        assert data.status_code == 200
        assert data.json()["data_origin"] == "synthetic_demo"
        forbidden = {"name", "phone", "email", "address", "message", "customer_name"}
        assert forbidden.isdisjoint(data.json()["columns"])
        assert {
            "region_group",
            "age_band",
            "signup_step",
            "error_category",
            "complaint_theme",
        }.issubset(data.json()["columns"])
        assert all(forbidden.isdisjoint(row) for row in data.json()["rows"])

        audit = client.get(f"/v1/taskviews/{view['id']}/audit-events", headers=requester_headers)
        assert audit.status_code == 200
        assert [event["action"] for event in reversed(audit.json())] == [
            "created",
            "submitted",
            "approved_alternative",
        ]

        dashboard = client.get("/v1/dashboard?period_days=7", headers=requester_headers)
        assert dashboard.status_code == 200
        assert dashboard.json()["counters"]["active_task_views"] == 1
        assert dashboard.json()["counters"]["connected_sources"] == 3

    get_settings.cache_clear()


def test_page_contracts_keep_object_level_authorization(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()

    with TestClient(app) as client:
        _, first_headers = signup(client, "first")
        _, second_headers = signup(client, "second")
        response = client.post(
            "/v1/taskviews/preview",
            headers=first_headers,
            json={
                "purpose": "고객 문의 유형을 집계해 콘텐츠 우선순위를 결정하고 싶다",
                "ttl_days": 7,
            },
        )
        assert response.status_code == 200
        view_id = response.json()["id"]

        protected_paths = [
            f"/v1/taskviews/{view_id}/compilation",
            f"/v1/taskviews/{view_id}/artifacts",
            f"/v1/taskviews/{view_id}/data",
            f"/v1/taskviews/{view_id}/audit-events",
            f"/v1/taskviews/{view_id}/discovery",
            f"/v1/taskviews/{view_id}/approval-status",
            f"/v1/taskviews/{view_id}/analytics",
        ]
        for path in protected_paths:
            assert client.get(path, headers=second_headers).status_code == 404

    get_settings.cache_clear()


def test_creation_journey_is_refresh_safe_and_submission_is_idempotent(monkeypatch):
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    get_settings.cache_clear()
    owner_email, owner_password = seed_owner()

    with TestClient(app) as client:
        _, requester_headers = signup(client, "journey")
        workspace_id = client.get("/v1/workspace", headers=requester_headers).json()["id"]
        grant_workspace_role(owner_email, workspace_id, "data_owner")
        created = client.post(
            "/v1/taskviews/preview",
            headers=requester_headers,
            json={
                "purpose": "일본 iOS 신규 사용자의 최근 회원가입 이탈 원인을 찾고 싶습니다.",
                "audience": "product",
                "ttl_days": 7,
                "region": "JP",
                "output_mode": "dashboard_api",
            },
        )
        assert created.status_code == 200
        view_id = created.json()["id"]

        discovery = client.get(f"/v1/taskviews/{view_id}/discovery", headers=requester_headers)
        assert discovery.status_code == 200
        assert discovery.json()["completion_percent"] == 100
        assert [source["source_key"] for source in discovery.json()["sources"]] == [
            "product",
            "operations",
            "voc",
        ]
        assert discovery.json()["reviewed_field_count"] == 10
        assert any(
            field["name"] == "exact_address" and field["decision"] == "generalize"
            for source in discovery.json()["sources"]
            for field in source["fields"]
        )

        first_submit = client.post(f"/v1/taskviews/{view_id}/submit", headers=requester_headers)
        assert first_submit.status_code == 200
        assert first_submit.json()["request_id"].startswith("REQ-")
        assert first_submit.json()["idempotent_replay"] is False

        repeated_submit = client.post(f"/v1/taskviews/{view_id}/submit", headers=requester_headers)
        assert repeated_submit.status_code == 200
        assert repeated_submit.json()["request_id"] == first_submit.json()["request_id"]
        assert repeated_submit.json()["idempotent_replay"] is True

        status_response = client.get(
            f"/v1/taskviews/{view_id}/approval-status", headers=requester_headers
        )
        assert status_response.status_code == 200
        assert status_response.json()["submitted"] is True
        assert status_response.json()["queue_position"] == 1
        assert len(status_response.json()["timeline"]) == 4

        owner_login = client.post(
            "/v1/auth/login", json={"email": owner_email, "password": owner_password}
        )
        owner_headers = {"authorization": f"Bearer {owner_login.json()['session_token']}"}
        approved = client.post(
            f"/v1/approval-requests/{view_id}/decision",
            headers=owner_headers,
            json={"decision": "approve", "reason": "목적과 최소화 변환 확인"},
        )
        assert approved.status_code == 200

        analytics = client.get(
            f"/v1/taskviews/{view_id}/analytics?period_days=7&region=JP&os=iOS&cohort=new",
            headers=requester_headers,
        )
        assert analytics.status_code == 200
        assert analytics.json()["data_origin"] == "synthetic_demo"
        assert analytics.json()["direct_identifier_count"] == 0
        assert analytics.json()["record_count"] > 0
        assert "signup_step" in analytics.json()["grouped_insights"]

        async def expire_view() -> None:
            connection = await asyncpg.connect(get_settings().taskview_database_url)
            try:
                await connection.execute(
                    """
                    UPDATE task_views
                    SET payload = jsonb_set(
                        payload,
                        '{evidence,expires_at}',
                        '"2000-01-01T00:00:00Z"'::jsonb
                    )
                    WHERE id = $1
                    """,
                    view_id,
                )
            finally:
                await connection.close()

        asyncio.run(expire_view())
        assert (
            client.get(f"/v1/taskviews/{view_id}/data", headers=requester_headers).status_code
            == 410
        )
        assert (
            client.get(f"/v1/taskviews/{view_id}/analytics", headers=requester_headers).status_code
            == 410
        )

    get_settings.cache_clear()
