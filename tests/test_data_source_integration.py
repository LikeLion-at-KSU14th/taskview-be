import asyncio
import json
import os
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from taskview_be.config import get_settings
from taskview_be.data_source_runtime import (
    DataSourceRuntimeConfig,
    PostgreSQLConnectionSpec,
    secured_postgresql_connection,
)
from taskview_be.main import app

TEST_DOMAIN = "data-source-integration.taskview.dev"
TEST_PASSWORD = "Needex-DataSource-Test!2026"
DELIVERY_KEY = Fernet.generate_key().decode()
DATA_SOURCE_KEY = Fernet.generate_key().decode()
DATABASE_PASSWORD = "taskview-data-source-secret-not-plaintext"
DATABASE_USERNAME = "taskview_catalog_integration"


def run(coroutine):
    return asyncio.run(coroutine)


async def cleanup_rows() -> None:
    connection = await asyncpg.connect(get_settings().taskview_database_url)
    try:
        await connection.execute(
            "DELETE FROM users WHERE email LIKE $1",
            f"%@{TEST_DOMAIN}",
        )
    finally:
        await connection.close()


async def prepare_catalog_role() -> None:
    connection = await asyncpg.connect(get_settings().taskview_database_url)
    try:
        await connection.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = '{DATABASE_USERNAME}'
                ) THEN
                    CREATE ROLE {DATABASE_USERNAME} LOGIN PASSWORD '{DATABASE_PASSWORD}';
                END IF;
            END $$;
            ALTER ROLE {DATABASE_USERNAME} LOGIN PASSWORD '{DATABASE_PASSWORD}';
            GRANT CONNECT ON DATABASE taskview TO {DATABASE_USERNAME};
            GRANT pg_read_all_data TO {DATABASE_USERNAME};
            """
        )
    finally:
        await connection.close()


async def drop_catalog_role() -> None:
    connection = await asyncpg.connect(get_settings().taskview_database_url)
    try:
        await connection.execute(
            f"""
            REVOKE pg_read_all_data FROM {DATABASE_USERNAME};
            REVOKE CONNECT ON DATABASE taskview FROM {DATABASE_USERNAME};
            DROP ROLE IF EXISTS {DATABASE_USERNAME};
            """
        )
    finally:
        await connection.close()


@pytest.fixture(autouse=True)
def docker_data_source_environment(monkeypatch):
    allowed = os.environ.get("TASKVIEW_DATA_SOURCE_ALLOWED_HOSTNAMES", "")
    if "postgres" not in {value.strip() for value in allowed.split(",")}:
        pytest.skip("The real data-source integration suite runs on the Docker network")
    monkeypatch.setenv("TASKVIEW_BE_FAKE_AI", "true")
    monkeypatch.setenv("TASKVIEW_EXPOSE_DEV_TOKENS", "true")
    monkeypatch.setenv("TASKVIEW_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("TASKVIEW_DELIVERY_ENCRYPTION_KEY", DELIVERY_KEY)
    monkeypatch.setenv("TASKVIEW_DATA_SOURCE_ENCRYPTION_KEY", DATA_SOURCE_KEY)
    monkeypatch.setenv("TASKVIEW_DATA_SOURCE_ALLOWED_HOSTNAMES", "postgres")
    monkeypatch.setenv("TASKVIEW_DATA_SOURCE_ALLOWED_CIDRS", "172.16.0.0/12")
    monkeypatch.setenv("TASKVIEW_DATA_SOURCE_REQUIRE_TLS", "false")
    monkeypatch.setenv("TASKVIEW_DATA_SOURCE_VERIFY_TLS", "false")
    get_settings.cache_clear()
    run(prepare_catalog_role())
    run(cleanup_rows())
    yield
    get_settings.cache_clear()
    run(cleanup_rows())
    run(drop_catalog_role())
    get_settings.cache_clear()


def signup_owner(client: TestClient, prefix: str) -> tuple[dict, dict[str, str], dict]:
    email = f"{prefix}-{uuid4().hex[:10]}@{TEST_DOMAIN}"
    signup = client.post(
        "/v1/auth/signup",
        json={
            "email": email,
            "display_name": f"{prefix} owner",
            "password": TEST_PASSWORD,
        },
    )
    assert signup.status_code == 201
    session = signup.json()
    headers = {"authorization": f"Bearer {session['session_token']}"}
    verified = client.post(
        "/v1/auth/email-verifications/confirm",
        json={"token": session["verification_token"]},
    )
    assert verified.status_code == 200
    workspace_response = client.post(
        "/v1/workspaces",
        headers=headers,
        json={
            "name": f"{prefix} workspace",
            "region": "KR-11",
            "default_ttl_days": 7,
            "member_role": "data_owner",
        },
    )
    assert workspace_response.status_code == 201
    workspace = workspace_response.json()
    completed = client.post(
        f"/v1/workspaces/{workspace['id']}/onboarding/complete",
        headers=headers,
        json={"skipped_invitations": True},
    )
    assert completed.status_code == 200
    return session, headers, workspace


def connection_payload(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "engine": "PostgreSQL",
        "name": "Needex Metadata DB",
        "organization": "Needex Integration",
        "host": "postgres",
        "port": "5432",
        "database": "taskview",
        "username": DATABASE_USERNAME,
        "password": DATABASE_PASSWORD,
        "tls": False,
    }
    payload.update(changes)
    return payload


def completion_payload(job_id: str) -> dict[str, str]:
    return {
        "job_id": job_id,
        "owner": "Integration Data Owner",
        "region": "Docker · Internal",
        "policy": "metadata-read-only",
    }


def test_real_postgresql_scan_persists_catalog_and_is_one_time(monkeypatch):
    with TestClient(app) as client:
        _, owner_a, workspace_a = signup_owner(client, "source-a")
        _, owner_b, _workspace_b = signup_owner(client, "source-b")

        initial = client.get("/v1/ui/data-sources", headers=owner_a)
        assert initial.status_code == 200
        assert initial.json()["stats"] == {
            "connected": 3,
            "builtIn": 3,
            "workspaceConnected": 0,
            "fields": initial.json()["stats"]["fields"],
            "pii": initial.json()["stats"]["pii"],
            "activeViews": 0,
        }
        assert {source["sourceType"] for source in initial.json()["sources"]} == {"public-live"}

        tested = client.post(
            "/v1/ui/data-sources/test",
            headers=owner_a,
            json=connection_payload(),
        )
        assert tested.status_code == 200
        assert tested.json()["success"] is True
        assert tested.json()["read_only"] is True
        assert tested.json()["tls"] is False
        assert "password" not in tested.text.casefold()
        assert "postgresql://" not in tested.text.casefold()

        scanned = client.post(
            "/v1/ui/data-sources/scan",
            headers=owner_a,
            json=connection_payload(),
        )
        assert scanned.status_code == 200
        scan = scanned.json()
        assert scan["state"] == "complete"
        assert scan["table_count"] > 0
        assert scan["field_count"] >= scan["table_count"]
        assert scan["sensitive_field_count"] > 0
        assert scan["raw_rows_returned"] == 0
        assert DATABASE_PASSWORD not in scanned.text

        cross_workspace = client.post(
            "/v1/ui/data-sources/scan/complete",
            headers=owner_b,
            json=completion_payload(scan["job_id"]),
        )
        assert cross_workspace.status_code == 404

        completed = client.post(
            "/v1/ui/data-sources/scan/complete",
            headers=owner_a,
            json=completion_payload(scan["job_id"]),
        )
        assert completed.status_code == 200
        source_id = completed.json()["source_id"]
        assert client.get(f"/v1/ui/data-sources/{source_id}", headers=owner_b).status_code == 404
        replay = client.post(
            "/v1/ui/data-sources/scan/complete",
            headers=owner_a,
            json=completion_payload(scan["job_id"]),
        )
        assert replay.status_code == 409

        overview = client.get("/v1/ui/data-sources", headers=owner_a)
        assert overview.status_code == 200
        assert overview.json()["stats"]["connected"] == 4
        assert overview.json()["stats"]["builtIn"] == 3
        assert overview.json()["stats"]["workspaceConnected"] == 1
        persisted_summary = next(
            source for source in overview.json()["sources"] if source["id"] == source_id
        )
        assert persisted_summary["sourceType"] == "workspace"
        assert persisted_summary["name"] == "Needex Metadata DB"

        detail = client.get(f"/v1/ui/data-sources/{source_id}", headers=owner_a)
        assert detail.status_code == 200
        assert detail.json()["sourceType"] == "workspace"
        assert detail.json()["fields"]
        assert DATABASE_PASSWORD not in detail.text

        async def inspect_persistence() -> asyncpg.Record:
            connection = await asyncpg.connect(get_settings().taskview_database_url)
            try:
                row = await connection.fetchrow(
                    """
                    SELECT
                        job.state, job.credential_ciphertext AS job_ciphertext,
                        source.credential_ciphertext AS source_ciphertext,
                        source.connection_metadata::text AS metadata_text,
                        source.catalog::text AS catalog_text,
                        source.raw_rows_returned, source.workspace_id
                    FROM data_source_scan_jobs job
                    JOIN workspace_data_sources source ON source.scan_job_id = job.id
                    WHERE job.id = $1::uuid
                    """,
                    scan["job_id"],
                )
                assert row is not None
                return row
            finally:
                await connection.close()

        persisted = run(inspect_persistence())
        assert persisted["state"] == "consumed"
        assert persisted["job_ciphertext"] is None
        assert persisted["raw_rows_returned"] == 0
        assert str(persisted["workspace_id"]) == workspace_a["id"]
        assert DATABASE_PASSWORD not in persisted["metadata_text"]
        assert DATABASE_PASSWORD not in persisted["catalog_text"]
        assert "postgresql://" not in persisted["metadata_text"].casefold()
        decrypted = Fernet(DATA_SOURCE_KEY.encode()).decrypt(bytes(persisted["source_ciphertext"]))
        credentials = json.loads(decrypted)
        assert credentials == {
            "version": 1,
            "username": DATABASE_USERNAME,
            "password": DATABASE_PASSWORD,
        }

        bad_host = client.post(
            "/v1/ui/data-sources/test",
            headers=owner_a,
            json=connection_payload(host="169.254.169.254"),
        )
        assert bad_host.status_code == 403
        assert DATABASE_PASSWORD not in bad_host.text

        unsupported = client.post(
            "/v1/ui/data-sources/test",
            headers=owner_a,
            json=connection_payload(engine="MySQL"),
        )
        assert unsupported.status_code == 422

        monkeypatch.setenv("TASKVIEW_DATA_SOURCE_REQUIRE_TLS", "true")
        get_settings.cache_clear()
        tls_refused = client.post(
            "/v1/ui/data-sources/test",
            headers=owner_a,
            json=connection_payload(tls=False),
        )
        assert tls_refused.status_code == 409
        monkeypatch.setenv("TASKVIEW_DATA_SOURCE_REQUIRE_TLS", "false")
        get_settings.cache_clear()

        unavailable = client.post(
            "/v1/ui/data-sources/test",
            headers=owner_a,
            json=connection_payload(password="wrong-password"),
        )
        assert unavailable.status_code == 503
        assert "wrong-password" not in unavailable.text


def test_real_postgresql_session_rejects_writes_and_expired_job_is_scrubbed():
    runtime_config = DataSourceRuntimeConfig(
        allowed_hostnames=frozenset({"postgres"}),
        allowed_cidrs=("172.16.0.0/12",),
        require_tls=False,
        verify_tls=False,
        connect_timeout_seconds=2,
        command_timeout_seconds=2,
    )
    connection_spec = PostgreSQLConnectionSpec(
        engine="PostgreSQL",
        host="postgres",
        port=5432,
        database="taskview",
        username="taskview",
        password="taskview",
        tls=False,
    )

    async def write_attempt() -> str:
        async with secured_postgresql_connection(connection_spec, runtime_config) as connection:
            assert await connection.fetchval("SHOW transaction_read_only") == "on"
            try:
                await connection.execute("CREATE TABLE taskview_must_never_be_created (id integer)")
            except asyncpg.PostgresError as error:
                return error.sqlstate or ""
        return "write-unexpectedly-succeeded"

    assert run(write_attempt()) == "25006"

    with TestClient(app) as client:
        _, owner, _workspace = signup_owner(client, "expired-source")
        scanned = client.post(
            "/v1/ui/data-sources/scan",
            headers=owner,
            json=connection_payload(),
        )
        assert scanned.status_code == 200
        job_id = scanned.json()["job_id"]

        async def expire_job() -> None:
            connection = await asyncpg.connect(get_settings().taskview_database_url)
            try:
                await connection.execute(
                    """
                    UPDATE data_source_scan_jobs
                    SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
                    WHERE id = $1::uuid
                    """,
                    job_id,
                )
            finally:
                await connection.close()

        run(expire_job())
        expired = client.post(
            "/v1/ui/data-sources/scan/complete",
            headers=owner,
            json=completion_payload(job_id),
        )
        assert expired.status_code == 410

        async def inspect_expired() -> asyncpg.Record:
            connection = await asyncpg.connect(get_settings().taskview_database_url)
            try:
                row = await connection.fetchrow(
                    """
                    SELECT state, credential_ciphertext, consumed_at
                    FROM data_source_scan_jobs WHERE id = $1::uuid
                    """,
                    job_id,
                )
                assert row is not None
                return row
            finally:
                await connection.close()

        expired_row = run(inspect_expired())
        assert expired_row["state"] == "expired"
        assert expired_row["credential_ciphertext"] is None
        assert expired_row["consumed_at"] is None
