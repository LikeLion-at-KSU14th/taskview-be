import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

import asyncpg

from .auth_schemas import Role, UserPublic
from .config import get_settings
from .experience_schemas import AuditEvent
from .schemas import NeedexResponse, RequesterSummary
from .workspace_schemas import (
    BatchInvitationResponse,
    InvitationResult,
    NotificationSettings,
    WorkspaceMember,
    WorkspacePublic,
)

CREATE_AUTH_TABLES = """
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    display_name VARCHAR(80) NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(24) NOT NULL DEFAULT 'requester'
        CHECK (role IN ('requester', 'data_owner', 'admin')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    email_verified_at TIMESTAMPTZ,
    marketing_opt_in BOOLEAN NOT NULL DEFAULT FALSE,
    onboarding_status VARCHAR(24) NOT NULL DEFAULT 'complete'
        CHECK (onboarding_status IN ('email_verification', 'workspace_setup', 'team_invite', 'complete')),
    auth_provider VARCHAR(16) NOT NULL DEFAULT 'password'
        CHECK (auth_provider IN ('password', 'google')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_normalized_email ON users (LOWER(email));

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS marketing_opt_in BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_status VARCHAR(24) NOT NULL DEFAULT 'complete';
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(16) NOT NULL DEFAULT 'password';
UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL
    AND onboarding_status = 'complete';

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_active
    ON auth_sessions (user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_one_time_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose VARCHAR(32) NOT NULL
        CHECK (purpose IN ('email_verification', 'password_reset')),
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_one_time_tokens_active
    ON auth_one_time_tokens (user_id, purpose, expires_at) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_delivery_outbox (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    purpose VARCHAR(32) NOT NULL
        CHECK (purpose IN ('email_verification', 'password_reset', 'workspace_invitation')),
    recipient_email TEXT NOT NULL,
    token_ciphertext BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    locked_at TIMESTAMPTZ,
    lock_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ
);
ALTER TABLE auth_delivery_outbox ADD COLUMN IF NOT EXISTS token_ciphertext BYTEA;
ALTER TABLE auth_delivery_outbox ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE auth_delivery_outbox
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE auth_delivery_outbox ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE auth_delivery_outbox ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
ALTER TABLE auth_delivery_outbox ADD COLUMN IF NOT EXISTS lock_id UUID;
ALTER TABLE auth_delivery_outbox ADD COLUMN IF NOT EXISTS failed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_auth_delivery_outbox_pending
    ON auth_delivery_outbox (next_attempt_at, created_at) WHERE delivered_at IS NULL;

CREATE TABLE IF NOT EXISTS oauth_states (
    token_hash CHAR(64) PRIMARY KEY,
    provider VARCHAR(16) NOT NULL CHECK (provider IN ('google')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider VARCHAR(16) NOT NULL CHECK (provider IN ('google')),
    provider_subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (provider, provider_subject),
    UNIQUE (provider, user_id)
);

CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    region VARCHAR(16) NOT NULL,
    default_ttl_days INTEGER NOT NULL DEFAULT 7 CHECK (default_ttl_days BETWEEN 1 AND 30),
    default_output_mode VARCHAR(24) NOT NULL DEFAULT 'dashboard_api'
        CHECK (default_output_mode IN ('dashboard', 'api', 'dashboard_api')),
    notifications JSONB NOT NULL DEFAULT '{
        "approval_requested": true,
        "view_approved": true,
        "ttl_expiring": true,
        "audit_events": false
    }'::jsonb,
    onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workspace_memberships (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(24) NOT NULL CHECK (role IN ('requester', 'data_owner', 'admin')),
    region VARCHAR(32) NOT NULL DEFAULT 'Seoul · KR',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS workspace_invitations (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role VARCHAR(24) NOT NULL CHECK (role IN ('requester', 'data_owner', 'admin')),
    token_hash CHAR(64) NOT NULL UNIQUE,
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_pending_invitation
    ON workspace_invitations (workspace_id, LOWER(email)) WHERE accepted_at IS NULL;

CREATE TABLE IF NOT EXISTS workspace_ui_settings (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    setting_key VARCHAR(40) NOT NULL,
    payload JSONB NOT NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, setting_key)
);

CREATE TABLE IF NOT EXISTS workspace_api_keys (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL,
    key_prefix VARCHAR(24) NOT NULL,
    secret_hash CHAR(64) NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id) ON DELETE SET NULL
);
ALTER TABLE workspace_api_keys
    ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE workspace_api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE workspace_api_keys
    ADD COLUMN IF NOT EXISTS revoked_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE workspace_api_keys
    DROP CONSTRAINT IF EXISTS workspace_api_keys_access_policy_check;
ALTER TABLE workspace_api_keys
    DROP CONSTRAINT IF EXISTS workspace_api_keys_revocation_metadata_check;
-- Keys issued by the old UI had neither scopes nor an expiry and were never a valid
-- API credential. Fail them closed instead of silently granting new capabilities.
UPDATE workspace_api_keys
SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
WHERE expires_at IS NULL OR CARDINALITY(scopes) = 0;
ALTER TABLE workspace_api_keys
    ADD CONSTRAINT workspace_api_keys_access_policy_check CHECK (
        scopes <@ ARRAY[
            'taskviews:artifacts:read',
            'taskviews:data:read',
            'taskviews:analytics:read'
        ]::TEXT[]
        AND CARDINALITY(scopes) <= 3
        AND (
            revoked_at IS NOT NULL
            OR (
                expires_at IS NOT NULL
                AND expires_at > created_at
                AND CARDINALITY(scopes) > 0
            )
        )
    );
ALTER TABLE workspace_api_keys
    ADD CONSTRAINT workspace_api_keys_revocation_metadata_check CHECK (
        revoked_by IS NULL OR revoked_at IS NOT NULL
    );
CREATE INDEX IF NOT EXISTS idx_workspace_api_keys_active
    ON workspace_api_keys (workspace_id, created_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_workspace_api_keys_authentication
    ON workspace_api_keys (secret_hash, expires_at) WHERE revoked_at IS NULL;
"""

CREATE_TASK_VIEWS_TABLE = """
CREATE TABLE IF NOT EXISTS task_views (
    id VARCHAR(32) PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL,
    purpose TEXT NOT NULL,
    audience VARCHAR(32) NOT NULL,
    ttl_days INTEGER NOT NULL CHECK (ttl_days BETWEEN 1 AND 30),
    payload JSONB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    content_hash CHAR(64),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE task_views
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE task_views ADD COLUMN IF NOT EXISTS workspace_id UUID;
ALTER TABLE task_views ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE task_views ADD COLUMN IF NOT EXISTS content_hash CHAR(64);
CREATE INDEX IF NOT EXISTS idx_task_views_status_created_at
    ON task_views (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_task_views_workspace_created_at
    ON task_views (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_task_views_created_by_created_at
    ON task_views (created_by, created_at DESC);

CREATE TABLE IF NOT EXISTS task_view_audit_events (
    id BIGSERIAL PRIMARY KEY,
    view_id VARCHAR(32) NOT NULL REFERENCES task_views(id) ON DELETE CASCADE,
    action VARCHAR(32) NOT NULL
        CHECK (action IN ('created', 'refined', 'submitted', 'approved', 'approved_alternative', 'rejected', 'downloaded')),
    actor_email TEXT,
    from_status VARCHAR(16),
    to_status VARCHAR(16) NOT NULL,
    reason TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_task_view_audit_events_view_created
    ON task_view_audit_events (view_id, created_at DESC);

ALTER TABLE task_view_audit_events
    DROP CONSTRAINT IF EXISTS task_view_audit_events_action_check;
ALTER TABLE task_view_audit_events
    ADD CONSTRAINT task_view_audit_events_action_check
    CHECK (action IN ('created', 'refined', 'submitted', 'approved', 'approved_alternative', 'rejected', 'downloaded'));

CREATE TABLE IF NOT EXISTS task_view_submissions (
    view_id VARCHAR(32) PRIMARY KEY REFERENCES task_views(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    request_id VARCHAR(32) NOT NULL UNIQUE,
    submitted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_owners JSONB NOT NULL DEFAULT '[]'::jsonb,
    submitted_revision INTEGER,
    submitted_content_hash CHAR(64),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE task_view_submissions ADD COLUMN IF NOT EXISTS workspace_id UUID;
ALTER TABLE task_view_submissions ADD COLUMN IF NOT EXISTS submitted_revision INTEGER;
ALTER TABLE task_view_submissions ADD COLUMN IF NOT EXISTS submitted_content_hash CHAR(64);
CREATE INDEX IF NOT EXISTS idx_task_view_submissions_submitted_at
    ON task_view_submissions (workspace_id, submitted_at, view_id);
"""

CREATE_DATA_SOURCE_TABLES = """
CREATE TABLE IF NOT EXISTS public_demo_source_snapshots (
    source_key VARCHAR(24) PRIMARY KEY CHECK (source_key IN ('product', 'operations', 'voc')),
    provider TEXT NOT NULL,
    official_url TEXT NOT NULL,
    license_url TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL,
    row_count INTEGER NOT NULL CHECK (row_count > 0),
    content_sha256 CHAR(64) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS public_demo_records (
    source_key VARCHAR(24) NOT NULL REFERENCES public_demo_source_snapshots(source_key)
        ON DELETE CASCADE,
    external_id_hash CHAR(64) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_key, external_id_hash)
);
CREATE INDEX IF NOT EXISTS idx_public_demo_records_source_observed
    ON public_demo_records (source_key, observed_at DESC);

CREATE TABLE IF NOT EXISTS data_source_scan_jobs (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state VARCHAR(16) NOT NULL DEFAULT 'complete'
        CHECK (state IN ('complete', 'consumed', 'expired')),
    name VARCHAR(100) NOT NULL,
    organization VARCHAR(100) NOT NULL,
    engine VARCHAR(24) NOT NULL CHECK (engine = 'PostgreSQL'),
    connection_metadata JSONB NOT NULL,
    credential_ciphertext BYTEA,
    table_count INTEGER NOT NULL CHECK (table_count >= 0),
    field_count INTEGER NOT NULL CHECK (field_count >= 0),
    sensitive_field_count INTEGER NOT NULL CHECK (sensitive_field_count >= 0),
    raw_rows_returned INTEGER NOT NULL DEFAULT 0 CHECK (raw_rows_returned = 0),
    catalog JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK (
        (state = 'complete' AND credential_ciphertext IS NOT NULL AND consumed_at IS NULL)
        OR (state = 'consumed' AND credential_ciphertext IS NULL AND consumed_at IS NOT NULL)
        OR (state = 'expired' AND credential_ciphertext IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_data_source_scan_jobs_workspace_creator
    ON data_source_scan_jobs (workspace_id, created_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_data_source_scan_jobs_expiry
    ON data_source_scan_jobs (expires_at) WHERE state = 'complete';

CREATE TABLE IF NOT EXISTS workspace_data_sources (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_job_id UUID NOT NULL UNIQUE REFERENCES data_source_scan_jobs(id) ON DELETE RESTRICT,
    name VARCHAR(100) NOT NULL,
    organization VARCHAR(100) NOT NULL,
    owner VARCHAR(100) NOT NULL,
    region VARCHAR(100) NOT NULL,
    policy VARCHAR(100) NOT NULL,
    engine VARCHAR(24) NOT NULL CHECK (engine = 'PostgreSQL'),
    connection_metadata JSONB NOT NULL,
    credential_ciphertext BYTEA NOT NULL,
    table_count INTEGER NOT NULL CHECK (table_count >= 0),
    field_count INTEGER NOT NULL CHECK (field_count >= 0),
    sensitive_field_count INTEGER NOT NULL CHECK (sensitive_field_count >= 0),
    raw_rows_returned INTEGER NOT NULL DEFAULT 0 CHECK (raw_rows_returned = 0),
    catalog JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'connected'
        CHECK (status IN ('connected', 'disconnected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_workspace_data_sources_workspace_sync
    ON workspace_data_sources (workspace_id, last_synced_at DESC);
"""


@dataclass(frozen=True)
class UserAuthRecord:
    user: UserPublic
    password_hash: str
    is_active: bool
    failed_login_attempts: int
    locked_until: datetime | None


@dataclass(frozen=True)
class ApprovalSubmissionRecord:
    request_id: str
    view_id: str
    submitted_by: str | None
    assigned_owners: list[str]
    submitted_revision: int | None
    submitted_content_hash: str | None
    submitted_at: datetime


@dataclass(frozen=True)
class OutboxDeliveryRecord:
    id: str
    purpose: str
    recipient_email: str
    token_ciphertext: bytes
    expires_at: datetime
    attempts: int


@dataclass(frozen=True)
class WorkspaceMembershipRecord:
    workspace_id: str
    user_id: str
    role: Role


@dataclass(frozen=True)
class WorkspaceApiKeyRecord:
    id: str
    workspace_id: str
    name: str
    key_prefix: str
    scopes: tuple[str, ...]
    created_by: str | None
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None


@dataclass(frozen=True)
class ViewAccessRecord:
    view: NeedexResponse
    workspace_id: str
    member_role: Role


@dataclass(frozen=True)
class WorkspaceDataSourceRecord:
    id: str
    workspace_id: str
    created_by: str
    scan_job_id: str
    name: str
    organization: str
    owner: str
    region: str
    policy: str
    engine: str
    connection_metadata: dict[str, object]
    table_count: int
    field_count: int
    sensitive_field_count: int
    raw_rows_returned: int
    catalog: list[dict[str, object]]
    status: str
    created_at: datetime
    last_synced_at: datetime


@dataclass(frozen=True)
class DataSourceScanJobInput:
    name: str
    organization: str
    engine: str
    connection_metadata: dict[str, object]
    credential_ciphertext: bytes = field(repr=False)
    table_count: int = 0
    field_count: int = 0
    sensitive_field_count: int = 0
    raw_rows_returned: int = 0
    catalog: list[dict[str, object]] = field(default_factory=list)
    expires_at: datetime | None = None


class SubmissionSnapshotConflictError(Exception):
    pass


class InvitationInvalidError(Exception):
    pass


class InvitationEmailMismatchError(Exception):
    pass


class DataSourceScanJobNotFoundError(Exception):
    pass


class DataSourceScanJobExpiredError(Exception):
    pass


class DataSourceScanJobConsumedError(Exception):
    pass


class PostgresNeedexStore:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            self._database_url,
            min_size=1,
            max_size=10,
            command_timeout=10,
        )
        async with self._pool.acquire() as connection:
            await connection.execute(CREATE_AUTH_TABLES)
            await self._migrate_delivery_outbox(connection)
            await connection.execute(CREATE_TASK_VIEWS_TABLE)
            await self._migrate_tenant_scope(connection)
            await connection.execute(CREATE_DATA_SOURCE_TABLES)
            await connection.execute(
                "DELETE FROM auth_sessions WHERE expires_at <= CURRENT_TIMESTAMP OR revoked_at IS NOT NULL"
            )

    async def stop(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def ping(self) -> bool:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            return await connection.fetchval("SELECT 1") == 1

    async def replace_public_demo_snapshot(self, snapshot: object) -> int:
        from .public_demo import PublicSnapshot

        if not isinstance(snapshot, PublicSnapshot):
            raise TypeError("snapshot must be PublicSnapshot")
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                INSERT INTO public_demo_source_snapshots (
                    source_key, provider, official_url, license_url, fetched_at,
                    row_count, content_sha256, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
                ON CONFLICT (source_key) DO UPDATE SET
                    provider = EXCLUDED.provider,
                    official_url = EXCLUDED.official_url,
                    license_url = EXCLUDED.license_url,
                    fetched_at = EXCLUDED.fetched_at,
                    row_count = EXCLUDED.row_count,
                    content_sha256 = EXCLUDED.content_sha256,
                    updated_at = CURRENT_TIMESTAMP
                """,
                snapshot.source_key,
                snapshot.provider,
                snapshot.official_url,
                snapshot.license_url,
                snapshot.fetched_at,
                len(snapshot.records),
                snapshot.content_sha256,
            )
            await connection.execute(
                "DELETE FROM public_demo_records WHERE source_key = $1",
                snapshot.source_key,
            )
            await connection.executemany(
                """
                INSERT INTO public_demo_records (
                    source_key, external_id_hash, observed_at, payload, fetched_at
                ) VALUES ($1, $2, $3, $4::jsonb, $5)
                """,
                [
                    (
                        record.source_key,
                        record.external_id_hash,
                        record.observed_at,
                        json.dumps(record.payload),
                        snapshot.fetched_at,
                    )
                    for record in snapshot.records
                ],
            )
        return len(snapshot.records)

    async def list_public_demo_snapshots(self) -> list[dict[str, object]]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT source_key, provider, official_url, license_url, fetched_at,
                       row_count, content_sha256
                FROM public_demo_source_snapshots
                ORDER BY source_key
                """
            )
        return [dict(row) for row in rows]

    async def public_demo_preview(
        self,
        plan: object,
        *,
        minimum_group_size: int = 20,
        limit: int | None = 24,
    ) -> list[dict[str, str | int]]:
        from .public_demo import aggregate_records
        from .schemas import ViewPlan

        if not isinstance(plan, ViewPlan):
            raise TypeError("plan must be ViewPlan")
        pool = self._require_pool()
        records_by_source: dict[str, list[dict[str, object]]] = {}
        async with pool.acquire() as connection:
            for source_key in plan.selected_sources:
                rows = await connection.fetch(
                    """
                    SELECT payload
                    FROM public_demo_records
                    WHERE source_key = $1
                    ORDER BY observed_at DESC
                    LIMIT 10000
                    """,
                    source_key,
                )
                records_by_source[source_key] = [
                    json.loads(row["payload"])
                    if isinstance(row["payload"], str)
                    else dict(row["payload"])
                    for row in rows
                ]
        return aggregate_records(
            plan,
            records_by_source,
            minimum_group_size=minimum_group_size,
            limit=limit,
        )

    async def public_demo_export_rows(self, plan: object) -> list[dict[str, str | int | float]]:
        from .public_demo import project_public_records
        from .schemas import ViewPlan

        if not isinstance(plan, ViewPlan):
            raise TypeError("plan must be ViewPlan")
        pool = self._require_pool()
        records_by_source: dict[str, list[dict[str, object]]] = {}
        async with pool.acquire() as connection:
            for source_key in plan.selected_sources:
                rows = await connection.fetch(
                    """
                    SELECT payload
                    FROM public_demo_records
                    WHERE source_key = $1
                    ORDER BY observed_at DESC
                    LIMIT 10000
                    """,
                    source_key,
                )
                records_by_source[source_key] = [
                    json.loads(row["payload"])
                    if isinstance(row["payload"], str)
                    else dict(row["payload"])
                    for row in rows
                ]
        return project_public_records(plan, records_by_source)

    async def create_user(
        self,
        *,
        email: str,
        display_name: str,
        password_hash: str,
        role: Role = "requester",
        email_verified: bool = True,
        marketing_opt_in: bool = False,
        onboarding_status: str = "complete",
    ) -> UserPublic:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                INSERT INTO users (
                    id, email, display_name, password_hash, role, email_verified_at,
                    marketing_opt_in, onboarding_status
                )
                VALUES (
                    $1, LOWER($2), $3, $4, $5,
                    CASE WHEN $6 THEN CURRENT_TIMESTAMP ELSE NULL END, $7, $8
                )
                RETURNING id, email, display_name, role, created_at,
                          email_verified_at, onboarding_status, auth_provider
                """,
                uuid4(),
                email,
                display_name,
                password_hash,
                role,
                email_verified,
                marketing_opt_in,
                onboarding_status,
            )
        return self._to_user_public(row)

    async def get_user_for_auth(self, email: str) -> UserAuthRecord | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT id, email, display_name, role, created_at, password_hash, is_active,
                       failed_login_attempts, locked_until, email_verified_at,
                       onboarding_status, auth_provider
                FROM users
                WHERE LOWER(email) = LOWER($1)
                """,
                email,
            )
        if row is None:
            return None
        return UserAuthRecord(
            user=self._to_user_public(row),
            password_hash=row["password_hash"],
            is_active=row["is_active"],
            failed_login_attempts=row["failed_login_attempts"],
            locked_until=row["locked_until"],
        )

    async def record_login_failure(
        self, user_id: str, *, max_failures: int, lock_minutes: int
    ) -> None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """
                UPDATE users
                SET failed_login_attempts = failed_login_attempts + 1,
                    locked_until = CASE
                        WHEN failed_login_attempts + 1 >= $2
                        THEN CURRENT_TIMESTAMP + ($3 * INTERVAL '1 minute')
                        ELSE locked_until
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                """,
                UUID(user_id),
                max_failures,
                lock_minutes,
            )

    async def record_login_success(self, user_id: str) -> None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """
                UPDATE users
                SET failed_login_attempts = 0,
                    locked_until = NULL,
                    last_login_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                """,
                UUID(user_id),
            )

    async def mark_email_verified(self, user_id: str) -> UserPublic:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                UPDATE users
                SET email_verified_at = COALESCE(email_verified_at, CURRENT_TIMESTAMP),
                    onboarding_status = CASE
                        WHEN onboarding_status = 'email_verification' THEN 'workspace_setup'
                        ELSE onboarding_status
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                RETURNING id, email, display_name, role, created_at,
                          email_verified_at, onboarding_status, auth_provider
                """,
                UUID(user_id),
            )
        if row is None:
            raise RuntimeError("사용자를 찾을 수 없습니다.")
        return self._to_user_public(row)

    async def create_session(
        self, *, user_id: str, token_hash: str, expires_at: datetime
    ) -> datetime:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            return await connection.fetchval(
                """
                INSERT INTO auth_sessions (id, user_id, token_hash, expires_at)
                VALUES ($1, $2, $3, $4)
                RETURNING expires_at
                """,
                uuid4(),
                UUID(user_id),
                token_hash,
                expires_at,
            )

    async def get_user_by_session(self, token_hash: str) -> UserPublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """
                SELECT u.id, u.email, u.display_name, u.role, u.created_at,
                       u.email_verified_at, u.onboarding_status, u.auth_provider,
                       s.id AS session_id
                FROM auth_sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = $1
                  AND s.revoked_at IS NULL
                  AND s.expires_at > CURRENT_TIMESTAMP
                  AND u.is_active = TRUE
                FOR UPDATE OF s
                """,
                token_hash,
            )
            if row is None:
                return None
            await connection.execute(
                "UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = $1",
                row["session_id"],
            )
        return self._to_user_public(row)

    async def revoke_session(self, token_hash: str) -> None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = CURRENT_TIMESTAMP
                WHERE token_hash = $1 AND revoked_at IS NULL
                """,
                token_hash,
            )

    async def issue_one_time_token(
        self,
        *,
        user_id: str,
        purpose: str,
        token_hash: str,
        expires_at: datetime,
        recipient_email: str | None = None,
        token_ciphertext: bytes | None = None,
    ) -> datetime:
        if (recipient_email is None) != (token_ciphertext is None):
            raise ValueError("recipient_email과 token_ciphertext는 함께 제공해야 합니다.")
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                UPDATE auth_one_time_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL
                """,
                UUID(user_id),
                purpose,
            )
            persisted_expiry = await connection.fetchval(
                """
                INSERT INTO auth_one_time_tokens (
                    id, user_id, purpose, token_hash, expires_at
                ) VALUES ($1, $2, $3, $4, $5)
                RETURNING expires_at
                """,
                uuid4(),
                UUID(user_id),
                purpose,
                token_hash,
                expires_at,
            )
            if recipient_email is not None and token_ciphertext is not None:
                await self._insert_outbox_delivery(
                    connection,
                    user_id=UUID(user_id),
                    purpose=purpose,
                    recipient_email=recipient_email,
                    token_ciphertext=token_ciphertext,
                    expires_at=expires_at,
                )
            return persisted_expiry

    async def enqueue_auth_delivery(
        self,
        *,
        user_id: str | None,
        purpose: str,
        recipient_email: str,
        token_ciphertext: bytes,
        expires_at: datetime,
    ) -> None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await self._insert_outbox_delivery(
                connection,
                user_id=UUID(user_id) if user_id else None,
                purpose=purpose,
                recipient_email=recipient_email,
                token_ciphertext=token_ciphertext,
                expires_at=expires_at,
            )

    async def confirm_email_verification(self, token_hash: str) -> UserPublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """
                SELECT token.id AS token_id, user_record.id, user_record.email,
                       user_record.display_name, user_record.role, user_record.created_at,
                       user_record.email_verified_at, user_record.onboarding_status,
                       user_record.auth_provider
                FROM auth_one_time_tokens token
                JOIN users user_record ON user_record.id = token.user_id
                WHERE token.token_hash = $1
                  AND token.purpose = 'email_verification'
                  AND token.used_at IS NULL
                  AND token.expires_at > CURRENT_TIMESTAMP
                FOR UPDATE OF token, user_record
                """,
                token_hash,
            )
            if row is None:
                return None
            await connection.execute(
                "UPDATE auth_one_time_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = $1",
                row["token_id"],
            )
            updated = await connection.fetchrow(
                """
                UPDATE users
                SET email_verified_at = COALESCE(email_verified_at, CURRENT_TIMESTAMP),
                    onboarding_status = CASE
                        WHEN onboarding_status = 'email_verification' THEN 'workspace_setup'
                        ELSE onboarding_status
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                RETURNING id, email, display_name, role, created_at,
                          email_verified_at, onboarding_status, auth_provider
                """,
                row["id"],
            )
        return self._to_user_public(updated)

    async def reset_password_with_token(
        self, token_hash: str, new_password_hash: str
    ) -> UserPublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """
                SELECT token.id AS token_id, token.user_id
                FROM auth_one_time_tokens token
                WHERE token.token_hash = $1
                  AND token.purpose = 'password_reset'
                  AND token.used_at IS NULL
                  AND token.expires_at > CURRENT_TIMESTAMP
                FOR UPDATE OF token
                """,
                token_hash,
            )
            if row is None:
                return None
            await connection.execute(
                "UPDATE auth_one_time_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = $1",
                row["token_id"],
            )
            await connection.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = CURRENT_TIMESTAMP
                WHERE user_id = $1 AND revoked_at IS NULL
                """,
                row["user_id"],
            )
            updated = await connection.fetchrow(
                """
                UPDATE users
                SET password_hash = $2, failed_login_attempts = 0, locked_until = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                RETURNING id, email, display_name, role, created_at,
                          email_verified_at, onboarding_status, auth_provider
                """,
                row["user_id"],
                new_password_hash,
            )
        return self._to_user_public(updated)

    async def create_oauth_state(self, *, token_hash: str, expires_at: datetime) -> None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """
                INSERT INTO oauth_states (token_hash, provider, expires_at)
                VALUES ($1, 'google', $2)
                """,
                token_hash,
                expires_at,
            )

    async def consume_oauth_state(self, token_hash: str) -> bool:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            consumed = await connection.fetchval(
                """
                UPDATE oauth_states
                SET used_at = CURRENT_TIMESTAMP
                WHERE token_hash = $1
                  AND provider = 'google'
                  AND used_at IS NULL
                  AND expires_at > CURRENT_TIMESTAMP
                RETURNING TRUE
                """,
                token_hash,
            )
        return consumed is True

    async def get_or_create_google_user(
        self,
        *,
        subject: str,
        email: str,
        display_name: str,
        unusable_password_hash: str,
    ) -> UserPublic:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            linked = await connection.fetchrow(
                """
                SELECT user_record.id, user_record.email, user_record.display_name,
                       user_record.role, user_record.created_at,
                       user_record.email_verified_at, user_record.onboarding_status,
                       user_record.auth_provider
                FROM oauth_accounts account
                JOIN users user_record ON user_record.id = account.user_id
                WHERE account.provider = 'google' AND account.provider_subject = $1
                FOR UPDATE OF account, user_record
                """,
                subject,
            )
            if linked is not None:
                await connection.execute(
                    """
                    UPDATE oauth_accounts SET last_login_at = CURRENT_TIMESTAMP
                    WHERE provider = 'google' AND provider_subject = $1
                    """,
                    subject,
                )
                return self._to_user_public(linked)

            existing = await connection.fetchrow(
                """
                SELECT id, email, display_name, role, created_at,
                       email_verified_at, onboarding_status, auth_provider
                FROM users
                WHERE LOWER(email) = LOWER($1)
                FOR UPDATE
                """,
                email,
            )
            if existing is None:
                existing = await connection.fetchrow(
                    """
                    INSERT INTO users (
                        id, email, display_name, password_hash, role,
                        email_verified_at, onboarding_status, auth_provider
                    ) VALUES (
                        $1, LOWER($2), $3, $4, 'requester',
                        CURRENT_TIMESTAMP, 'workspace_setup', 'google'
                    )
                    RETURNING id, email, display_name, role, created_at,
                              email_verified_at, onboarding_status, auth_provider
                    """,
                    uuid4(),
                    email,
                    display_name,
                    unusable_password_hash,
                )
            else:
                existing = await connection.fetchrow(
                    """
                    UPDATE users
                    SET email_verified_at = COALESCE(email_verified_at, CURRENT_TIMESTAMP),
                        auth_provider = 'google',
                        onboarding_status = CASE
                            WHEN onboarding_status = 'email_verification' THEN 'workspace_setup'
                            ELSE onboarding_status
                        END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                    RETURNING id, email, display_name, role, created_at,
                              email_verified_at, onboarding_status, auth_provider
                    """,
                    existing["id"],
                )
            await connection.execute(
                """
                INSERT INTO oauth_accounts (provider, provider_subject, user_id)
                VALUES ('google', $1, $2)
                """,
                subject,
                existing["id"],
            )
        return self._to_user_public(existing)

    async def set_user_role(self, email: str, role: Role) -> UserPublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                UPDATE users
                SET role = $2, updated_at = CURRENT_TIMESTAMP
                WHERE LOWER(email) = LOWER($1)
                RETURNING id, email, display_name, role, created_at,
                          email_verified_at, onboarding_status, auth_provider
                """,
                email,
                role,
            )
        return None if row is None else self._to_user_public(row)

    async def create_workspace(
        self,
        *,
        user_id: str,
        name: str,
        region: str,
        default_ttl_days: int,
        member_role: Role,
    ) -> WorkspacePublic:
        pool = self._require_pool()
        workspace_id = uuid4()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                INSERT INTO workspaces (
                    id, name, region, default_ttl_days, created_by
                ) VALUES ($1, $2, $3, $4, $5)
                """,
                workspace_id,
                name,
                region,
                default_ttl_days,
                UUID(user_id),
            )
            await connection.execute(
                """
                INSERT INTO workspace_memberships (workspace_id, user_id, role)
                VALUES ($1, $2, $3)
                """,
                workspace_id,
                UUID(user_id),
                member_role,
            )
            await connection.execute(
                """
                UPDATE users
                SET onboarding_status = 'team_invite', updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                """,
                UUID(user_id),
            )
            row = await self._workspace_row(connection, workspace_id, UUID(user_id))
        return self._to_workspace(row)

    async def get_current_workspace_membership(
        self, user_id: str, *, require_onboarding_complete: bool = False
    ) -> WorkspaceMembershipRecord | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT membership.workspace_id, membership.user_id, membership.role
                FROM workspace_memberships membership
                JOIN workspaces workspace ON workspace.id = membership.workspace_id
                WHERE membership.user_id = $1
                  AND ($2::boolean = FALSE OR workspace.onboarding_complete = TRUE)
                ORDER BY membership.joined_at DESC, membership.workspace_id DESC
                LIMIT 1
                """,
                UUID(user_id),
                require_onboarding_complete,
            )
        if row is None:
            return None
        return WorkspaceMembershipRecord(
            workspace_id=str(row["workspace_id"]),
            user_id=str(row["user_id"]),
            role=row["role"],
        )

    async def get_workspace_for_user(self, user_id: str) -> WorkspacePublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT workspace.*, membership.role AS member_role
                FROM workspace_memberships membership
                JOIN workspaces workspace ON workspace.id = membership.workspace_id
                WHERE membership.user_id = $1
                ORDER BY membership.joined_at DESC
                LIMIT 1
                """,
                UUID(user_id),
            )
        return None if row is None else self._to_workspace(row)

    async def update_workspace(
        self, workspace_id: str, user_id: str, changes: dict[str, object]
    ) -> WorkspacePublic | None:
        allowed = {"name", "region", "default_ttl_days", "default_output_mode"}
        selected = {key: value for key, value in changes.items() if key in allowed}
        if not selected:
            return await self.get_workspace_for_user(user_id)
        assignments = ", ".join(
            f"{column} = ${index}" for index, column in enumerate(selected, start=2)
        )
        values = list(selected.values())
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            permitted = await connection.fetchval(
                """
                SELECT TRUE FROM workspace_memberships
                WHERE workspace_id = $1 AND user_id = $2 AND role = 'admin'
                """,
                UUID(workspace_id),
                UUID(user_id),
            )
            if permitted is not True:
                return None
            await connection.execute(
                f"UPDATE workspaces SET {assignments}, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                UUID(workspace_id),
                *values,
            )
            row = await self._workspace_row(connection, UUID(workspace_id), UUID(user_id))
        return self._to_workspace(row)

    async def update_workspace_notifications(
        self,
        workspace_id: str,
        user_id: str,
        notifications: NotificationSettings,
    ) -> WorkspacePublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            updated = await connection.fetchval(
                """
                UPDATE workspaces workspace
                SET notifications = $3::jsonb, updated_at = CURRENT_TIMESTAMP
                WHERE workspace.id = $1
                  AND EXISTS (
                      SELECT 1 FROM workspace_memberships membership
                      WHERE membership.workspace_id = workspace.id
                        AND membership.user_id = $2
                        AND membership.role = 'admin'
                  )
                RETURNING TRUE
                """,
                UUID(workspace_id),
                UUID(user_id),
                notifications.model_dump_json(),
            )
            if updated is not True:
                return None
            row = await self._workspace_row(connection, UUID(workspace_id), UUID(user_id))
        return self._to_workspace(row)

    async def create_workspace_invitations(
        self,
        *,
        workspace_id: str,
        invited_by: str,
        invitations: list[tuple[str, Role, str, bytes, datetime]],
        onboarding_only: bool = False,
    ) -> BatchInvitationResponse | None:
        pool = self._require_pool()
        results: list[InvitationResult] = []
        seen: set[str] = set()
        async with pool.acquire() as connection, connection.transaction():
            permitted = await connection.fetchval(
                """
                SELECT TRUE
                FROM workspace_memberships membership
                JOIN workspaces workspace ON workspace.id = membership.workspace_id
                WHERE membership.workspace_id = $1
                  AND membership.user_id = $2
                  AND (
                      (
                          $3::boolean = TRUE
                          AND workspace.created_by = membership.user_id
                          AND workspace.onboarding_complete = FALSE
                      )
                      OR (
                          $3::boolean = FALSE
                          AND membership.role = 'admin'
                      )
                  )
                """,
                UUID(workspace_id),
                UUID(invited_by),
                onboarding_only,
            )
            if permitted is not True:
                return None
            for email, role, token_hash, token_ciphertext, expires_at in invitations:
                normalized = email.casefold()
                if normalized in seen:
                    results.append(InvitationResult(email=email, role=role, status="duplicate"))
                    continue
                seen.add(normalized)
                member = await connection.fetchval(
                    """
                    SELECT TRUE
                    FROM workspace_memberships membership
                    JOIN users user_record ON user_record.id = membership.user_id
                    WHERE membership.workspace_id = $1
                      AND LOWER(user_record.email) = LOWER($2)
                    """,
                    UUID(workspace_id),
                    email,
                )
                if member is True:
                    results.append(
                        InvitationResult(email=email, role=role, status="already_member")
                    )
                    continue
                await connection.execute(
                    """
                    INSERT INTO workspace_invitations (
                        id, workspace_id, email, role, token_hash, invited_by, expires_at
                    ) VALUES ($1, $2, LOWER($3), $4, $5, $6, $7)
                    ON CONFLICT (workspace_id, LOWER(email)) WHERE accepted_at IS NULL
                    DO UPDATE SET role = EXCLUDED.role, token_hash = EXCLUDED.token_hash,
                                  invited_by = EXCLUDED.invited_by,
                                  expires_at = EXCLUDED.expires_at,
                                  created_at = CURRENT_TIMESTAMP
                    """,
                    uuid4(),
                    UUID(workspace_id),
                    email,
                    role,
                    token_hash,
                    UUID(invited_by),
                    expires_at,
                )
                await self._insert_outbox_delivery(
                    connection,
                    user_id=None,
                    purpose="workspace_invitation",
                    recipient_email=email,
                    token_ciphertext=token_ciphertext,
                    expires_at=expires_at,
                )
                results.append(InvitationResult(email=email, role=role, status="invited"))
        return BatchInvitationResponse(
            workspace_id=workspace_id,
            results=results,
            invited_count=sum(result.status == "invited" for result in results),
        )

    async def accept_workspace_invitation(
        self,
        *,
        token_hash: str,
        user_id: str,
        user_email: str,
    ) -> WorkspacePublic:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            invitation = await connection.fetchrow(
                """
                SELECT id, workspace_id, email, role, expires_at, accepted_at
                FROM workspace_invitations
                WHERE token_hash = $1
                FOR UPDATE
                """,
                token_hash,
            )
            if (
                invitation is None
                or invitation["accepted_at"] is not None
                or invitation["expires_at"] <= datetime.now(invitation["expires_at"].tzinfo)
            ):
                raise InvitationInvalidError
            if invitation["email"].casefold() != user_email.casefold():
                raise InvitationEmailMismatchError
            await connection.execute(
                """
                INSERT INTO workspace_memberships (workspace_id, user_id, role)
                VALUES ($1, $2, $3)
                ON CONFLICT (workspace_id, user_id) DO UPDATE SET
                    role = EXCLUDED.role,
                    joined_at = CURRENT_TIMESTAMP
                """,
                invitation["workspace_id"],
                UUID(user_id),
                invitation["role"],
            )
            await connection.execute(
                """
                UPDATE workspace_invitations
                SET accepted_at = CURRENT_TIMESTAMP
                WHERE id = $1 AND accepted_at IS NULL
                """,
                invitation["id"],
            )
            await connection.execute(
                """
                UPDATE users
                SET onboarding_status = 'complete', updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                """,
                UUID(user_id),
            )
            workspace_row = await self._workspace_row(
                connection, invitation["workspace_id"], UUID(user_id)
            )
        return self._to_workspace(workspace_row)

    async def complete_workspace_onboarding(
        self, workspace_id: str, user_id: str
    ) -> WorkspacePublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            updated = await connection.fetchval(
                """
                UPDATE workspaces workspace
                SET onboarding_complete = TRUE, updated_at = CURRENT_TIMESTAMP
                WHERE workspace.id = $1
                  AND workspace.created_by = $2
                  AND EXISTS (
                      SELECT 1 FROM workspace_memberships membership
                      WHERE membership.workspace_id = workspace.id
                        AND membership.user_id = $2
                  )
                RETURNING TRUE
                """,
                UUID(workspace_id),
                UUID(user_id),
            )
            if updated is not True:
                return None
            await connection.execute(
                """
                UPDATE users SET onboarding_status = 'complete', updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                """,
                UUID(user_id),
            )
            row = await self._workspace_row(connection, UUID(workspace_id), UUID(user_id))
        return self._to_workspace(row)

    async def list_workspace_members(self, user_id: str) -> list[WorkspaceMember] | None:
        workspace = await self.get_workspace_for_user(user_id)
        if workspace is None:
            return None
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT user_record.id, user_record.display_name, user_record.email,
                       membership.role, membership.region, membership.joined_at
                FROM workspace_memberships membership
                JOIN users user_record ON user_record.id = membership.user_id
                WHERE membership.workspace_id = $1
                ORDER BY membership.joined_at, user_record.email
                """,
                UUID(workspace.id),
            )
        return [
            WorkspaceMember(
                id=str(row["id"]),
                display_name=row["display_name"],
                email=row["email"],
                role=row["role"],
                region=row["region"],
                joined_at=row["joined_at"],
            )
            for row in rows
        ]

    async def update_account_name(self, user_id: str, display_name: str) -> UserPublic | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                UPDATE users SET display_name = $2, updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                RETURNING id, email, display_name, role, created_at,
                          email_verified_at, onboarding_status, auth_provider
                """,
                UUID(user_id),
                display_name,
            )
        return None if row is None else self._to_user_public(row)

    async def get_workspace_ui_setting(
        self, user_id: str, setting_key: str
    ) -> dict[str, object] | None:
        workspace = await self.get_workspace_for_user(user_id)
        if workspace is None:
            return None
        pool = self._require_pool()
        async with pool.acquire() as connection:
            payload = await connection.fetchval(
                """
                SELECT payload FROM workspace_ui_settings
                WHERE workspace_id = $1 AND setting_key = $2
                """,
                UUID(workspace.id),
                setting_key,
            )
        if isinstance(payload, str):
            payload = json.loads(payload)
        return payload

    async def set_workspace_ui_setting(
        self, user_id: str, setting_key: str, payload: dict[str, object]
    ) -> bool:
        workspace = await self.get_workspace_for_user(user_id)
        if workspace is None:
            return False
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """
                INSERT INTO workspace_ui_settings (
                    workspace_id, setting_key, payload, updated_by
                ) VALUES ($1, $2, $3::jsonb, $4)
                ON CONFLICT (workspace_id, setting_key) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = CURRENT_TIMESTAMP
                """,
                UUID(workspace.id),
                setting_key,
                json.dumps(payload, ensure_ascii=False),
                UUID(user_id),
            )
        return True

    async def create_workspace_api_key(
        self,
        *,
        workspace_id: str,
        created_by: str,
        name: str,
        key_prefix: str,
        secret_hash: str,
        scopes: tuple[str, ...],
        expires_at: datetime,
    ) -> WorkspaceApiKeyRecord | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                INSERT INTO workspace_api_keys (
                    id, workspace_id, name, key_prefix, secret_hash, scopes,
                    created_by, expires_at
                )
                SELECT $1, membership.workspace_id, $4, $5, $6, $7::TEXT[], $3, $8
                FROM workspace_memberships membership
                JOIN workspaces workspace ON workspace.id = membership.workspace_id
                WHERE membership.workspace_id = $2
                  AND membership.user_id = $3
                  AND membership.role = 'admin'
                  AND workspace.onboarding_complete = TRUE
                RETURNING id, workspace_id, name, key_prefix, scopes, created_by,
                          created_at, expires_at, last_used_at, revoked_at, revoked_by
                """,
                uuid4(),
                UUID(workspace_id),
                UUID(created_by),
                name,
                key_prefix,
                secret_hash,
                list(scopes),
                expires_at,
            )
        return None if row is None else self._to_workspace_api_key(row)

    async def list_workspace_api_keys(self, workspace_id: str) -> list[WorkspaceApiKeyRecord]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT id, workspace_id, name, key_prefix, scopes, created_by,
                       created_at, expires_at, last_used_at, revoked_at, revoked_by
                FROM workspace_api_keys
                WHERE workspace_id = $1
                ORDER BY created_at DESC, id DESC
                """,
                UUID(workspace_id),
            )
        return [self._to_workspace_api_key(row) for row in rows]

    async def revoke_workspace_api_key(
        self, *, workspace_id: str, key_id: str, revoked_by: str
    ) -> WorkspaceApiKeyRecord | None:
        try:
            parsed_key_id = UUID(key_id)
        except ValueError:
            return None
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                UPDATE workspace_api_keys api_key
                SET revoked_at = CURRENT_TIMESTAMP, revoked_by = $3
                FROM workspace_memberships membership
                WHERE api_key.id = $1
                  AND api_key.workspace_id = $2
                  AND membership.workspace_id = api_key.workspace_id
                  AND membership.user_id = $3
                  AND membership.role = 'admin'
                  AND api_key.revoked_at IS NULL
                RETURNING api_key.id, api_key.workspace_id, api_key.name,
                          api_key.key_prefix, api_key.scopes, api_key.created_by,
                          api_key.created_at, api_key.expires_at, api_key.last_used_at,
                          api_key.revoked_at, api_key.revoked_by
                """,
                parsed_key_id,
                UUID(workspace_id),
                UUID(revoked_by),
            )
        return None if row is None else self._to_workspace_api_key(row)

    async def authenticate_workspace_api_key(
        self, secret_hash: str
    ) -> WorkspaceApiKeyRecord | None:
        """Authenticate an active key without recording a use until the request succeeds."""
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT api_key.id, api_key.workspace_id, api_key.name,
                       api_key.key_prefix, api_key.scopes, api_key.created_by,
                       api_key.created_at, api_key.expires_at, api_key.last_used_at,
                       api_key.revoked_at, api_key.revoked_by
                FROM workspace_api_keys api_key
                JOIN workspaces workspace ON workspace.id = api_key.workspace_id
                WHERE api_key.secret_hash = $1
                  AND workspace.onboarding_complete = TRUE
                  AND api_key.revoked_at IS NULL
                  AND api_key.expires_at > CURRENT_TIMESTAMP
                  AND CARDINALITY(api_key.scopes) > 0
                """,
                secret_hash,
            )
        return None if row is None else self._to_workspace_api_key(row)

    async def record_workspace_api_key_use(self, *, key_id: str, workspace_id: str) -> bool:
        """Atomically record a successful request while rechecking revocation and expiry."""
        pool = self._require_pool()
        async with pool.acquire() as connection:
            updated = await connection.fetchval(
                """
                UPDATE workspace_api_keys api_key
                SET last_used_at = CURRENT_TIMESTAMP
                FROM workspaces workspace
                WHERE api_key.id = $1
                  AND api_key.workspace_id = $2
                  AND api_key.workspace_id = workspace.id
                  AND workspace.onboarding_complete = TRUE
                  AND api_key.revoked_at IS NULL
                  AND api_key.expires_at > CURRENT_TIMESTAMP
                  AND CARDINALITY(api_key.scopes) > 0
                RETURNING api_key.id
                """,
                UUID(key_id),
                UUID(workspace_id),
            )
        return updated is not None

    async def create_data_source_scan_job(
        self,
        *,
        workspace_id: str,
        created_by: str,
        job: DataSourceScanJobInput,
    ) -> str:
        if job.engine != "PostgreSQL":
            raise ValueError("Only PostgreSQL scan jobs can be persisted")
        if job.raw_rows_returned != 0:
            raise ValueError("Data-source scan jobs cannot contain raw rows")
        if not job.credential_ciphertext:
            raise ValueError("Encrypted data-source credentials are required")
        if job.expires_at is None:
            raise ValueError("A data-source scan job expiry is required")
        metadata = self._safe_connection_metadata(job.connection_metadata)
        job_id = uuid4()
        pool = self._require_pool()
        async with pool.acquire() as connection:
            inserted = await connection.fetchval(
                """
                INSERT INTO data_source_scan_jobs (
                    id, workspace_id, created_by, name, organization, engine,
                    connection_metadata, credential_ciphertext, table_count,
                    field_count, sensitive_field_count, raw_rows_returned,
                    catalog, expires_at
                )
                SELECT
                    $1, membership.workspace_id, membership.user_id, $4, $5, $6,
                    $7::jsonb, $8, $9, $10, $11, 0, $12::jsonb, $13
                FROM workspace_memberships membership
                JOIN workspaces workspace ON workspace.id = membership.workspace_id
                WHERE membership.workspace_id = $2
                  AND membership.user_id = $3
                  AND membership.role IN ('data_owner', 'admin')
                  AND workspace.onboarding_complete = TRUE
                RETURNING id
                """,
                job_id,
                UUID(workspace_id),
                UUID(created_by),
                job.name,
                job.organization,
                job.engine,
                json.dumps(metadata, ensure_ascii=False),
                job.credential_ciphertext,
                job.table_count,
                job.field_count,
                job.sensitive_field_count,
                json.dumps(job.catalog, ensure_ascii=False),
                job.expires_at,
            )
        if inserted is None:
            raise DataSourceScanJobNotFoundError
        return str(inserted)

    async def complete_data_source_scan_job(
        self,
        *,
        job_id: str,
        workspace_id: str,
        created_by: str,
        owner: str,
        region: str,
        policy: str,
    ) -> WorkspaceDataSourceRecord:
        try:
            parsed_job_id = UUID(job_id)
            parsed_workspace_id = UUID(workspace_id)
            parsed_creator_id = UUID(created_by)
        except ValueError:
            raise DataSourceScanJobNotFoundError from None

        pool = self._require_pool()
        failure: type[Exception] | None = None
        source_row: asyncpg.Record | None = None
        async with pool.acquire() as connection, connection.transaction():
            job_row = await connection.fetchrow(
                """
                SELECT id, state, expires_at <= CURRENT_TIMESTAMP AS is_expired
                FROM data_source_scan_jobs
                WHERE id = $1 AND workspace_id = $2 AND created_by = $3
                FOR UPDATE
                """,
                parsed_job_id,
                parsed_workspace_id,
                parsed_creator_id,
            )
            if job_row is None:
                failure = DataSourceScanJobNotFoundError
            elif job_row["state"] == "consumed":
                failure = DataSourceScanJobConsumedError
            elif job_row["state"] == "expired" or job_row["is_expired"]:
                await connection.execute(
                    """
                    UPDATE data_source_scan_jobs
                    SET state = 'expired', credential_ciphertext = NULL
                    WHERE id = $1
                    """,
                    parsed_job_id,
                )
                failure = DataSourceScanJobExpiredError
            else:
                source_id = uuid4()
                source_row = await connection.fetchrow(
                    """
                    INSERT INTO workspace_data_sources (
                        id, workspace_id, created_by, scan_job_id, name,
                        organization, owner, region, policy, engine,
                        connection_metadata, credential_ciphertext, table_count,
                        field_count, sensitive_field_count, raw_rows_returned,
                        catalog
                    )
                    SELECT
                        $2, job.workspace_id, job.created_by, job.id, job.name,
                        job.organization, $3, $4, $5, job.engine,
                        job.connection_metadata, job.credential_ciphertext,
                        job.table_count, job.field_count,
                        job.sensitive_field_count, 0, job.catalog
                    FROM data_source_scan_jobs job
                    WHERE job.id = $1 AND job.state = 'complete'
                      AND job.credential_ciphertext IS NOT NULL
                    RETURNING
                        id, workspace_id, created_by, scan_job_id, name,
                        organization, owner, region, policy, engine,
                        connection_metadata, table_count, field_count,
                        sensitive_field_count, raw_rows_returned, catalog,
                        status, created_at, last_synced_at
                    """,
                    parsed_job_id,
                    source_id,
                    owner,
                    region,
                    policy,
                )
                if source_row is None:
                    failure = DataSourceScanJobConsumedError
                else:
                    await connection.execute(
                        """
                        UPDATE data_source_scan_jobs
                        SET state = 'consumed', credential_ciphertext = NULL,
                            consumed_at = CURRENT_TIMESTAMP
                        WHERE id = $1 AND state = 'complete'
                        """,
                        parsed_job_id,
                    )
        if failure is not None:
            raise failure
        if source_row is None:
            raise DataSourceScanJobNotFoundError
        return self._to_workspace_data_source(source_row)

    async def list_workspace_data_sources(
        self, *, workspace_id: str, user_id: str
    ) -> list[WorkspaceDataSourceRecord]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT
                    source.id, source.workspace_id, source.created_by,
                    source.scan_job_id, source.name, source.organization,
                    source.owner, source.region, source.policy, source.engine,
                    source.connection_metadata, source.table_count,
                    source.field_count, source.sensitive_field_count,
                    source.raw_rows_returned, source.catalog, source.status,
                    source.created_at, source.last_synced_at
                FROM workspace_data_sources source
                JOIN workspace_memberships membership
                  ON membership.workspace_id = source.workspace_id
                WHERE source.workspace_id = $1 AND membership.user_id = $2
                ORDER BY source.last_synced_at DESC, source.id
                """,
                UUID(workspace_id),
                UUID(user_id),
            )
        return [self._to_workspace_data_source(row) for row in rows]

    async def get_workspace_data_source(
        self, source_id: str, *, workspace_id: str, user_id: str
    ) -> WorkspaceDataSourceRecord | None:
        try:
            parsed_source_id = UUID(source_id)
        except ValueError:
            return None
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT
                    source.id, source.workspace_id, source.created_by,
                    source.scan_job_id, source.name, source.organization,
                    source.owner, source.region, source.policy, source.engine,
                    source.connection_metadata, source.table_count,
                    source.field_count, source.sensitive_field_count,
                    source.raw_rows_returned, source.catalog, source.status,
                    source.created_at, source.last_synced_at
                FROM workspace_data_sources source
                JOIN workspace_memberships membership
                  ON membership.workspace_id = source.workspace_id
                WHERE source.id = $1 AND source.workspace_id = $2
                  AND membership.user_id = $3
                """,
                parsed_source_id,
                UUID(workspace_id),
                UUID(user_id),
            )
        return None if row is None else self._to_workspace_data_source(row)

    async def save(
        self,
        view: NeedexResponse,
        *,
        workspace_id: str,
        actor_email: str | None = None,
    ) -> NeedexResponse:
        payload = self._payload_json(view)
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                INSERT INTO task_views (
                    id, workspace_id, status, purpose, audience, ttl_days, payload,
                    revision, content_hash, created_at, created_by, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7::jsonb,
                    $8, $9, $10, $11, CURRENT_TIMESTAMP
                )
                """,
                view.id,
                UUID(workspace_id),
                view.status,
                view.purpose,
                view.audience,
                view.ttl_days,
                payload,
                view.revision,
                self._hash_payload(payload),
                view.created_at,
                UUID(view.created_by) if view.created_by else None,
            )
            await self._insert_audit_event(
                connection,
                view_id=view.id,
                action="created",
                actor_email=actor_email,
                from_status=None,
                to_status=view.status,
                reason=None,
                metadata={"created_by": view.created_by or "", "revision": view.revision},
            )
        return view

    async def save_if_revision(
        self,
        view: NeedexResponse,
        *,
        workspace_id: str,
        expected_revision: int,
        expected_status: str,
        action: str = "refined",
        actor_email: str | None = None,
        reason: str | None = None,
        metadata: dict[str, str | int | bool] | None = None,
        require_submission_match: bool = False,
        forbid_pending_submission: bool = False,
        expected_payload: str | None = None,
        expected_content_hash: str | None = None,
    ) -> bool:
        """Revision CAS with optional atomic approval-snapshot enforcement."""
        next_revision = expected_revision + 1
        next_view = view.model_copy(update={"revision": next_revision}, deep=True)
        payload = self._payload_json(next_view)
        content_hash = self._hash_payload(payload)
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            updated = await connection.fetchval(
                """
                UPDATE task_views AS view SET
                    status = $2,
                    purpose = $3,
                    audience = $4,
                    ttl_days = $5,
                    payload = $6::jsonb,
                    created_by = $7,
                    revision = $8,
                    content_hash = $9,
                    updated_at = CURRENT_TIMESTAMP
                WHERE view.id = $1
                  AND view.workspace_id = $10
                  AND view.revision = $11
                  AND view.status = $12
                  AND (
                      $13::boolean = FALSE
                      OR EXISTS (
                          SELECT 1
                          FROM task_view_submissions submission
                          WHERE submission.view_id = view.id
                            AND submission.workspace_id = view.workspace_id
                            AND submission.submitted_revision = view.revision
                            AND submission.submitted_content_hash = view.content_hash
                      )
                  )
                  AND (
                      $14::boolean = FALSE
                      OR NOT (
                          view.status IN ('proposed', 'blocked')
                          AND EXISTS (
                              SELECT 1 FROM task_view_submissions submission
                              WHERE submission.view_id = view.id
                                AND submission.workspace_id = view.workspace_id
                          )
                      )
                  )
                  AND (
                      $15::text IS NULL
                      OR (
                          view.content_hash = $15
                          AND view.payload = $16::jsonb
                      )
                  )
                RETURNING TRUE
                """,
                view.id,
                view.status,
                view.purpose,
                view.audience,
                view.ttl_days,
                payload,
                UUID(view.created_by) if view.created_by else None,
                next_revision,
                content_hash,
                UUID(workspace_id),
                expected_revision,
                expected_status,
                require_submission_match,
                forbid_pending_submission,
                expected_content_hash,
                expected_payload,
            )
            if updated is True:
                await self._insert_audit_event(
                    connection,
                    view_id=view.id,
                    action=action,
                    actor_email=actor_email,
                    from_status=expected_status,
                    to_status=view.status,
                    reason=reason,
                    metadata={**(metadata or {}), "revision": next_revision},
                )
        if updated is True:
            view.revision = next_revision
        return updated is True

    async def get(self, view_id: str, *, workspace_id: str) -> NeedexResponse | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT tv.payload, tv.revision, u.email AS requester_email,
                       u.display_name AS requester_display_name
                FROM task_views tv
                LEFT JOIN users u ON u.id = tv.created_by
                WHERE tv.id = $1 AND tv.workspace_id = $2
                """,
                view_id,
                UUID(workspace_id),
            )
        return None if row is None else self._decode_view(row)

    async def get_view_for_member(
        self,
        view_id: str,
        user_id: str,
        *,
        workspace_id: str,
        require_creator: bool = False,
        require_approver: bool = False,
        require_submission: bool = False,
    ) -> ViewAccessRecord | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT view.payload, view.revision, view.workspace_id,
                       membership.role AS member_role,
                       requester.email AS requester_email,
                       requester.display_name AS requester_display_name
                FROM task_views view
                JOIN workspace_memberships membership
                  ON membership.workspace_id = view.workspace_id
                 AND membership.user_id = $2
                LEFT JOIN users requester ON requester.id = view.created_by
                LEFT JOIN task_view_submissions submission
                  ON submission.view_id = view.id
                 AND submission.workspace_id = view.workspace_id
                WHERE view.id = $1
                  AND view.workspace_id = $6
                  AND (
                      ($3::boolean = TRUE AND view.created_by = $2)
                      OR (
                          $3::boolean = FALSE
                          AND $4::boolean = FALSE
                          AND (
                              membership.role IN ('data_owner', 'admin')
                              OR view.created_by = $2
                          )
                      )
                      OR (
                          $4::boolean = TRUE
                          AND membership.role IN ('data_owner', 'admin')
                      )
                  )
                  AND (
                      $5::boolean = FALSE
                      OR (
                          submission.view_id IS NOT NULL
                          AND view.status IN ('proposed', 'blocked')
                          AND submission.submitted_revision = view.revision
                          AND submission.submitted_content_hash = view.content_hash
                      )
                  )
                """,
                view_id,
                UUID(user_id),
                require_creator,
                require_approver,
                require_submission,
                UUID(workspace_id),
            )
        if row is None:
            return None
        return ViewAccessRecord(
            view=self._decode_view(row),
            workspace_id=str(row["workspace_id"]),
            member_role=row["member_role"],
        )

    async def list_views_for_member(
        self, *, user_id: str, workspace_id: str, limit: int = 50
    ) -> list[NeedexResponse]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT view.payload, view.revision, requester.email AS requester_email,
                       requester.display_name AS requester_display_name
                FROM task_views view
                JOIN workspace_memberships membership
                  ON membership.workspace_id = view.workspace_id
                 AND membership.user_id = $1
                LEFT JOIN users requester ON requester.id = view.created_by
                WHERE view.workspace_id = $2
                  AND (
                      membership.role IN ('data_owner', 'admin')
                      OR view.created_by = membership.user_id
                  )
                ORDER BY view.created_at DESC
                LIMIT $3
                """,
                UUID(user_id),
                UUID(workspace_id),
                limit,
            )
        return [self._decode_view(row) for row in rows]

    async def list_submitted_views_for_approver(
        self, *, user_id: str, workspace_id: str, limit: int = 100
    ) -> list[NeedexResponse]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT view.payload, view.revision, requester.email AS requester_email,
                       requester.display_name AS requester_display_name
                FROM task_views view
                JOIN workspace_memberships membership
                  ON membership.workspace_id = view.workspace_id
                 AND membership.user_id = $1
                 AND membership.role IN ('data_owner', 'admin')
                JOIN task_view_submissions submission
                  ON submission.view_id = view.id
                 AND submission.workspace_id = view.workspace_id
                 AND submission.submitted_revision = view.revision
                 AND submission.submitted_content_hash = view.content_hash
                LEFT JOIN users requester ON requester.id = view.created_by
                WHERE view.workspace_id = $2
                  AND view.status IN ('proposed', 'blocked')
                  AND submission.submitted_by IS DISTINCT FROM $1
                ORDER BY submission.submitted_at, view.id
                LIMIT $3
                """,
                UUID(user_id),
                UUID(workspace_id),
                limit,
            )
        return [self._decode_view(row) for row in rows]

    async def submit_for_approval(
        self,
        view_id: str,
        *,
        workspace_id: str,
        submitted_by: str,
        actor_email: str,
        assigned_owners: list[str],
    ) -> tuple[ApprovalSubmissionRecord, bool]:
        """Create an immutable approval submission, returning an existing record on retry."""
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            view_row = await connection.fetchrow(
                """
                SELECT status, revision, content_hash, payload
                FROM task_views
                WHERE id = $1 AND workspace_id = $2 AND created_by = $3
                FOR UPDATE
                """,
                view_id,
                UUID(workspace_id),
                UUID(submitted_by),
            )
            if view_row is None:
                raise KeyError(view_id)
            if self._hash_payload(view_row["payload"]) != view_row["content_hash"]:
                raise SubmissionSnapshotConflictError(view_id)
            existing = await connection.fetchrow(
                """
                SELECT request_id, view_id, submitted_by, assigned_owners,
                       submitted_revision, submitted_content_hash, submitted_at
                FROM task_view_submissions
                WHERE view_id = $1 AND workspace_id = $2
                """,
                view_id,
                UUID(workspace_id),
            )
            if existing is not None:
                if (
                    existing["submitted_revision"] == view_row["revision"]
                    and existing["submitted_content_hash"] == view_row["content_hash"]
                ):
                    return self._to_submission(existing), True
                if (
                    existing["submitted_revision"] is not None
                    or existing["submitted_content_hash"] is not None
                ):
                    raise SubmissionSnapshotConflictError(view_id)
                refreshed = await connection.fetchrow(
                    """
                    UPDATE task_view_submissions
                    SET submitted_by = $3,
                        assigned_owners = $4::jsonb,
                        submitted_revision = $5,
                        submitted_content_hash = $6,
                        submitted_at = CURRENT_TIMESTAMP
                    WHERE view_id = $1 AND workspace_id = $2
                    RETURNING request_id, view_id, submitted_by, assigned_owners,
                              submitted_revision, submitted_content_hash, submitted_at
                    """,
                    view_id,
                    UUID(workspace_id),
                    UUID(submitted_by),
                    json.dumps(assigned_owners, ensure_ascii=False),
                    view_row["revision"],
                    view_row["content_hash"],
                )
                return self._to_submission(refreshed), False

            row = await connection.fetchrow(
                """
                INSERT INTO task_view_submissions (
                    view_id, workspace_id, request_id, submitted_by, assigned_owners,
                    submitted_revision, submitted_content_hash
                ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
                RETURNING request_id, view_id, submitted_by, assigned_owners,
                          submitted_revision, submitted_content_hash, submitted_at
                """,
                view_id,
                UUID(workspace_id),
                f"REQ-{uuid4().hex[:8].upper()}",
                UUID(submitted_by),
                json.dumps(assigned_owners, ensure_ascii=False),
                view_row["revision"],
                view_row["content_hash"],
            )
            await self._insert_audit_event(
                connection,
                view_id=view_id,
                action="submitted",
                actor_email=actor_email,
                from_status=view_row["status"],
                to_status=view_row["status"],
                reason="Data Owner approval requested",
                metadata={
                    "assigned_owner_count": len(assigned_owners),
                    "submitted_revision": view_row["revision"],
                },
            )
        return self._to_submission(row), False

    async def get_submission(
        self, view_id: str, *, workspace_id: str
    ) -> ApprovalSubmissionRecord | None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT request_id, view_id, submitted_by, assigned_owners,
                       submitted_revision, submitted_content_hash, submitted_at
                FROM task_view_submissions
                WHERE view_id = $1 AND workspace_id = $2
                """,
                view_id,
                UUID(workspace_id),
            )
        return None if row is None else self._to_submission(row)

    async def approval_queue_metrics(
        self, *, workspace_id: str, view_id: str | None = None
    ) -> tuple[int | None, int]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            total = await connection.fetchval(
                """
                SELECT COUNT(*)
                FROM task_view_submissions submission
                JOIN task_views view ON view.id = submission.view_id
                WHERE view.status IN ('proposed', 'blocked')
                  AND view.workspace_id = $1
                  AND submission.workspace_id = view.workspace_id
                  AND submission.submitted_revision = view.revision
                  AND submission.submitted_content_hash = view.content_hash
                """,
                UUID(workspace_id),
            )
            if view_id is None:
                return None, int(total)
            submitted_at = await connection.fetchval(
                """
                SELECT submitted_at FROM task_view_submissions
                WHERE view_id = $1 AND workspace_id = $2
                """,
                view_id,
                UUID(workspace_id),
            )
            if submitted_at is None:
                return None, int(total)
            position = await connection.fetchval(
                """
                SELECT COUNT(*)
                FROM task_view_submissions submission
                JOIN task_views view ON view.id = submission.view_id
                WHERE view.status IN ('proposed', 'blocked')
                  AND view.workspace_id = $1
                  AND submission.workspace_id = view.workspace_id
                  AND submission.submitted_revision = view.revision
                  AND submission.submitted_content_hash = view.content_hash
                  AND (submission.submitted_at, submission.view_id) <= ($2, $3)
                """,
                UUID(workspace_id),
                submitted_at,
                view_id,
            )
        return int(position), int(total)

    async def list_audit_events(
        self, view_id: str, *, workspace_id: str, limit: int = 100
    ) -> list[AuditEvent]:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT event.id, event.view_id, event.action, event.actor_email,
                       event.from_status, event.to_status, event.reason,
                       event.metadata, event.created_at
                FROM task_view_audit_events event
                JOIN task_views view ON view.id = event.view_id
                WHERE event.view_id = $1 AND view.workspace_id = $2
                ORDER BY event.created_at DESC, event.id DESC
                LIMIT $3
                """,
                view_id,
                UUID(workspace_id),
                limit,
            )
        return [
            AuditEvent(
                id=row["id"],
                view_id=row["view_id"],
                action=row["action"],
                actor_email=row["actor_email"],
                from_status=row["from_status"],
                to_status=row["to_status"],
                reason=row["reason"],
                metadata=json.loads(row["metadata"])
                if isinstance(row["metadata"], str)
                else row["metadata"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    async def record_data_download(
        self,
        *,
        view_id: str,
        workspace_id: str,
        actor_email: str | None,
        row_count: int,
        filter_field: str | None,
        filter_value: str | None,
    ) -> bool:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            exists = await connection.fetchval(
                "SELECT EXISTS(SELECT 1 FROM task_views WHERE id = $1 AND workspace_id = $2)",
                view_id,
                UUID(workspace_id),
            )
            if not exists:
                return False
            await self._insert_audit_event(
                connection,
                view_id=view_id,
                action="downloaded",
                actor_email=actor_email,
                from_status="approved",
                to_status="approved",
                reason="안전 데이터 CSV 다운로드",
                metadata={
                    "format": "csv",
                    "row_count": row_count,
                    "filter_field": filter_field or "",
                    "filter_value": filter_value or "",
                },
            )
        return True

    async def claim_outbox_deliveries(
        self,
        *,
        worker_id: str,
        limit: int,
        max_attempts: int,
        claim_seconds: int,
    ) -> list[OutboxDeliveryRecord]:
        pool = self._require_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                UPDATE auth_delivery_outbox
                SET failed_at = CURRENT_TIMESTAMP,
                    token_ciphertext = NULL,
                    last_error = 'Delivery token expired before send',
                    locked_at = NULL,
                    lock_id = NULL
                WHERE delivered_at IS NULL
                  AND failed_at IS NULL
                  AND expires_at <= CURRENT_TIMESTAMP
                """
            )
            rows = await connection.fetch(
                """
                WITH candidates AS (
                    SELECT id
                    FROM auth_delivery_outbox
                    WHERE delivered_at IS NULL
                      AND failed_at IS NULL
                      AND token_ciphertext IS NOT NULL
                      AND attempts < $2
                      AND next_attempt_at <= CURRENT_TIMESTAMP
                      AND (
                          locked_at IS NULL
                          OR locked_at < CURRENT_TIMESTAMP - make_interval(secs => $3)
                      )
                    ORDER BY next_attempt_at, created_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT $1
                )
                UPDATE auth_delivery_outbox delivery
                SET locked_at = CURRENT_TIMESTAMP, lock_id = $4
                FROM candidates
                WHERE delivery.id = candidates.id
                RETURNING delivery.id, delivery.purpose, delivery.recipient_email,
                          delivery.token_ciphertext, delivery.expires_at, delivery.attempts
                """,
                limit,
                max_attempts,
                claim_seconds,
                UUID(worker_id),
            )
        return [self._to_outbox_delivery(row) for row in rows]

    async def mark_outbox_delivered(self, delivery_id: str, *, worker_id: str) -> bool:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            updated = await connection.fetchval(
                """
                UPDATE auth_delivery_outbox
                SET delivered_at = CURRENT_TIMESTAMP,
                    token_ciphertext = NULL,
                    last_error = NULL,
                    locked_at = NULL,
                    lock_id = NULL
                WHERE id = $1 AND lock_id = $2
                  AND delivered_at IS NULL AND failed_at IS NULL
                RETURNING TRUE
                """,
                UUID(delivery_id),
                UUID(worker_id),
            )
        return updated is True

    async def mark_outbox_failed(
        self,
        delivery_id: str,
        *,
        worker_id: str,
        error: str,
        max_attempts: int,
    ) -> bool:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            updated = await connection.fetchval(
                """
                UPDATE auth_delivery_outbox
                SET attempts = attempts + 1,
                    last_error = LEFT($3, 500),
                    next_attempt_at = CURRENT_TIMESTAMP + make_interval(
                        secs => LEAST(3600, (5 * power(2, LEAST(attempts, 10)))::integer)
                    ),
                    failed_at = CASE
                        WHEN attempts + 1 >= $4 THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END,
                    token_ciphertext = CASE
                        WHEN attempts + 1 >= $4 THEN NULL
                        ELSE token_ciphertext
                    END,
                    locked_at = NULL,
                    lock_id = NULL
                WHERE id = $1 AND lock_id = $2
                  AND delivered_at IS NULL AND failed_at IS NULL
                RETURNING TRUE
                """,
                UUID(delivery_id),
                UUID(worker_id),
                error,
                max_attempts,
            )
        return updated is True

    async def clear(self) -> None:
        pool = self._require_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                "TRUNCATE TABLE task_view_audit_events, task_view_submissions, task_views RESTART IDENTITY"
            )

    async def _migrate_delivery_outbox(self, connection: asyncpg.Connection) -> None:
        """Remove legacy plaintext delivery tokens and install retry-safe outbox columns."""
        async with connection.transaction():
            has_plaintext_column = await connection.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'auth_delivery_outbox'
                      AND column_name = 'delivery_token'
                )
                """
            )
            if has_plaintext_column:
                await connection.execute(
                    """
                    UPDATE auth_delivery_outbox
                    SET token_ciphertext = NULL,
                        failed_at = COALESCE(failed_at, CURRENT_TIMESTAMP),
                        last_error = 'Legacy plaintext delivery discarded; reissue required'
                    WHERE delivery_token IS NOT NULL
                    """
                )
                await connection.execute(
                    "ALTER TABLE auth_delivery_outbox DROP COLUMN delivery_token"
                )
            await connection.execute(
                """
                UPDATE auth_delivery_outbox
                SET failed_at = COALESCE(failed_at, CURRENT_TIMESTAMP),
                    last_error = COALESCE(last_error, 'Missing encrypted delivery payload')
                WHERE token_ciphertext IS NULL
                  AND delivered_at IS NULL
                  AND failed_at IS NULL;
                ALTER TABLE auth_delivery_outbox ALTER COLUMN user_id DROP NOT NULL;
                ALTER TABLE auth_delivery_outbox
                    DROP CONSTRAINT IF EXISTS auth_delivery_outbox_purpose_check;
                ALTER TABLE auth_delivery_outbox
                    ADD CONSTRAINT auth_delivery_outbox_purpose_check
                    CHECK (
                        purpose IN (
                            'email_verification', 'password_reset', 'workspace_invitation'
                        )
                    );
                ALTER TABLE auth_delivery_outbox
                    DROP CONSTRAINT IF EXISTS auth_delivery_outbox_attempts_check;
                ALTER TABLE auth_delivery_outbox
                    ADD CONSTRAINT auth_delivery_outbox_attempts_check CHECK (attempts >= 0);
                ALTER TABLE auth_delivery_outbox
                    DROP CONSTRAINT IF EXISTS auth_delivery_outbox_pending_ciphertext_check;
                ALTER TABLE auth_delivery_outbox
                    ADD CONSTRAINT auth_delivery_outbox_pending_ciphertext_check
                    CHECK (
                        delivered_at IS NOT NULL
                        OR failed_at IS NOT NULL
                        OR token_ciphertext IS NOT NULL
                    );
                DROP INDEX IF EXISTS idx_auth_delivery_outbox_pending;
                CREATE INDEX idx_auth_delivery_outbox_pending
                    ON auth_delivery_outbox (next_attempt_at, created_at)
                    WHERE delivered_at IS NULL AND failed_at IS NULL;
                """
            )

    async def _migrate_tenant_scope(self, connection: asyncpg.Connection) -> None:
        """Backfill legacy rows without granting historical global roles tenant access."""
        async with connection.transaction():
            creator_ids = await connection.fetch(
                """
                SELECT DISTINCT created_by
                FROM task_views
                WHERE workspace_id IS NULL AND created_by IS NOT NULL
                """
            )
            for creator_row in creator_ids:
                creator_id = creator_row["created_by"]
                workspace_id = await connection.fetchval(
                    """
                    SELECT workspace_id
                    FROM workspace_memberships
                    WHERE user_id = $1
                    ORDER BY joined_at DESC, workspace_id DESC
                    LIMIT 1
                    """,
                    creator_id,
                )
                if workspace_id is None:
                    workspace_id = uuid4()
                    await connection.execute(
                        """
                        INSERT INTO workspaces (
                            id, name, region, onboarding_complete, created_by
                        ) VALUES ($1, $2, 'GLOBAL', TRUE, $3)
                        """,
                        workspace_id,
                        f"Legacy Task Views {str(creator_id)[:8]}",
                        creator_id,
                    )
                    await connection.execute(
                        """
                        INSERT INTO workspace_memberships (workspace_id, user_id, role)
                        VALUES ($1, $2, 'requester')
                        ON CONFLICT (workspace_id, user_id) DO NOTHING
                        """,
                        workspace_id,
                        creator_id,
                    )
                await connection.execute(
                    """
                    UPDATE task_views
                    SET workspace_id = $1
                    WHERE workspace_id IS NULL AND created_by = $2
                    """,
                    workspace_id,
                    creator_id,
                )

            orphan_count = await connection.fetchval(
                "SELECT COUNT(*) FROM task_views WHERE workspace_id IS NULL"
            )
            if orphan_count:
                quarantine_workspace_id = uuid4()
                await connection.execute(
                    """
                    INSERT INTO workspaces (
                        id, name, region, onboarding_complete, created_by
                    ) VALUES ($1, 'Legacy Quarantine', 'GLOBAL', TRUE, NULL)
                    """,
                    quarantine_workspace_id,
                )
                await connection.execute(
                    """
                    UPDATE task_views
                    SET workspace_id = $1
                    WHERE workspace_id IS NULL
                    """,
                    quarantine_workspace_id,
                )

            unhashed_rows = await connection.fetch(
                "SELECT id, payload FROM task_views WHERE content_hash IS NULL"
            )
            for row in unhashed_rows:
                await connection.execute(
                    "UPDATE task_views SET content_hash = $2 WHERE id = $1",
                    row["id"],
                    self._hash_payload(row["payload"]),
                )

            await connection.execute(
                """
                UPDATE task_view_submissions submission
                SET workspace_id = view.workspace_id
                FROM task_views view
                WHERE submission.view_id = view.id
                  AND submission.workspace_id IS NULL
                """
            )
            await connection.execute(
                """
                ALTER TABLE task_views ALTER COLUMN workspace_id SET NOT NULL;
                ALTER TABLE task_views ALTER COLUMN content_hash SET NOT NULL;
                ALTER TABLE task_views ALTER COLUMN revision SET DEFAULT 1;
                ALTER TABLE task_view_submissions ALTER COLUMN workspace_id SET NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS uq_task_views_id_workspace
                    ON task_views (id, workspace_id);
                """
            )
            await connection.execute(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'task_views_workspace_id_fkey'
                    ) THEN
                        ALTER TABLE task_views
                        ADD CONSTRAINT task_views_workspace_id_fkey
                        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'task_views_revision_check'
                    ) THEN
                        ALTER TABLE task_views
                        ADD CONSTRAINT task_views_revision_check CHECK (revision >= 1);
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'task_view_submissions_workspace_id_fkey'
                    ) THEN
                        ALTER TABLE task_view_submissions
                        ADD CONSTRAINT task_view_submissions_workspace_id_fkey
                        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'task_view_submissions_view_workspace_fkey'
                    ) THEN
                        ALTER TABLE task_view_submissions
                        ADD CONSTRAINT task_view_submissions_view_workspace_fkey
                        FOREIGN KEY (view_id, workspace_id)
                        REFERENCES task_views(id, workspace_id) ON DELETE CASCADE;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'task_view_submissions_snapshot_pair_check'
                    ) THEN
                        ALTER TABLE task_view_submissions
                        ADD CONSTRAINT task_view_submissions_snapshot_pair_check
                        CHECK (
                            (submitted_revision IS NULL) =
                            (submitted_content_hash IS NULL)
                        );
                    END IF;
                END $$;
                """
            )

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgreSQL store has not been started")
        return self._pool

    @staticmethod
    async def _insert_outbox_delivery(
        connection: asyncpg.Connection,
        *,
        user_id: UUID | None,
        purpose: str,
        recipient_email: str,
        token_ciphertext: bytes,
        expires_at: datetime,
    ) -> None:
        await connection.execute(
            """
            INSERT INTO auth_delivery_outbox (
                id, user_id, purpose, recipient_email, token_ciphertext, expires_at
            ) VALUES ($1, $2, $3, LOWER($4), $5, $6)
            """,
            uuid4(),
            user_id,
            purpose,
            recipient_email,
            token_ciphertext,
            expires_at,
        )

    @staticmethod
    async def _insert_audit_event(
        connection: asyncpg.Connection,
        *,
        view_id: str,
        action: str,
        actor_email: str | None,
        from_status: str | None,
        to_status: str,
        reason: str | None,
        metadata: dict[str, str | int | bool],
    ) -> None:
        await connection.execute(
            """
            INSERT INTO task_view_audit_events (
                view_id, action, actor_email, from_status, to_status, reason, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            """,
            view_id,
            action,
            actor_email,
            from_status,
            to_status,
            reason,
            json.dumps(metadata, ensure_ascii=False),
        )

    @staticmethod
    async def _workspace_row(
        connection: asyncpg.Connection, workspace_id: UUID, user_id: UUID
    ) -> asyncpg.Record:
        row = await connection.fetchrow(
            """
            SELECT workspace.*, membership.role AS member_role
            FROM workspaces workspace
            JOIN workspace_memberships membership
              ON membership.workspace_id = workspace.id
            WHERE workspace.id = $1 AND membership.user_id = $2
            """,
            workspace_id,
            user_id,
        )
        if row is None:
            raise RuntimeError("Workspace membership disappeared during transaction")
        return row

    @staticmethod
    def _to_user_public(row: asyncpg.Record) -> UserPublic:
        return UserPublic(
            id=str(row["id"]),
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            created_at=row["created_at"],
            email_verified=row["email_verified_at"] is not None,
            onboarding_status=row["onboarding_status"],
            auth_provider=row["auth_provider"],
        )

    @staticmethod
    def _to_workspace(row: asyncpg.Record) -> WorkspacePublic:
        notifications = row["notifications"]
        if isinstance(notifications, str):
            notifications = json.loads(notifications)
        return WorkspacePublic(
            id=str(row["id"]),
            name=row["name"],
            region=row["region"],
            default_ttl_days=row["default_ttl_days"],
            default_output_mode=row["default_output_mode"],
            member_role=row["member_role"],
            onboarding_complete=row["onboarding_complete"],
            notifications=NotificationSettings.model_validate(notifications),
            created_at=row["created_at"],
        )

    @staticmethod
    def _to_workspace_api_key(row: asyncpg.Record) -> WorkspaceApiKeyRecord:
        return WorkspaceApiKeyRecord(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            name=row["name"],
            key_prefix=row["key_prefix"],
            scopes=tuple(row["scopes"]),
            created_by=str(row["created_by"]) if row["created_by"] else None,
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
            revoked_by=str(row["revoked_by"]) if row["revoked_by"] else None,
        )

    @staticmethod
    def _safe_connection_metadata(metadata: dict[str, object]) -> dict[str, object]:
        allowed_keys = {"engine", "host", "port", "database", "tls"}
        if set(metadata) != allowed_keys:
            raise ValueError("Connection metadata has an invalid shape")
        serialized = json.dumps(metadata, ensure_ascii=False).casefold()
        if "://" in serialized:
            raise ValueError("Connection metadata cannot contain a DSN")
        return metadata.copy()

    @staticmethod
    def _to_workspace_data_source(row: asyncpg.Record) -> WorkspaceDataSourceRecord:
        metadata = row["connection_metadata"]
        catalog = row["catalog"]
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        if isinstance(catalog, str):
            catalog = json.loads(catalog)
        return WorkspaceDataSourceRecord(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            created_by=str(row["created_by"]),
            scan_job_id=str(row["scan_job_id"]),
            name=row["name"],
            organization=row["organization"],
            owner=row["owner"],
            region=row["region"],
            policy=row["policy"],
            engine=row["engine"],
            connection_metadata=metadata,
            table_count=row["table_count"],
            field_count=row["field_count"],
            sensitive_field_count=row["sensitive_field_count"],
            raw_rows_returned=row["raw_rows_returned"],
            catalog=catalog,
            status=row["status"],
            created_at=row["created_at"],
            last_synced_at=row["last_synced_at"],
        )

    @staticmethod
    def _payload_json(view: NeedexResponse) -> str:
        return view.model_copy(update={"requester": None}).model_dump_json()

    @classmethod
    def view_snapshot(cls, view: NeedexResponse) -> tuple[str, str]:
        payload = cls._payload_json(view)
        return payload, cls._hash_payload(payload)

    @staticmethod
    def _hash_payload(payload: object) -> str:
        decoded = json.loads(payload) if isinstance(payload, str) else payload
        canonical = json.dumps(
            decoded,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _to_submission(row: asyncpg.Record) -> ApprovalSubmissionRecord:
        owners = row["assigned_owners"]
        if isinstance(owners, str):
            owners = json.loads(owners)
        return ApprovalSubmissionRecord(
            request_id=row["request_id"],
            view_id=row["view_id"],
            submitted_by=str(row["submitted_by"]) if row["submitted_by"] else None,
            assigned_owners=list(owners),
            submitted_revision=row["submitted_revision"],
            submitted_content_hash=row["submitted_content_hash"],
            submitted_at=row["submitted_at"],
        )

    @staticmethod
    def _to_outbox_delivery(row: asyncpg.Record) -> OutboxDeliveryRecord:
        return OutboxDeliveryRecord(
            id=str(row["id"]),
            purpose=row["purpose"],
            recipient_email=row["recipient_email"],
            token_ciphertext=bytes(row["token_ciphertext"]),
            expires_at=row["expires_at"],
            attempts=row["attempts"],
        )

    @staticmethod
    def _decode_view(row: asyncpg.Record) -> NeedexResponse:
        payload = row["payload"]
        decoded = json.loads(payload) if isinstance(payload, str) else payload
        view = NeedexResponse.model_validate(decoded)
        view.revision = row["revision"]
        if row["requester_email"] and row["requester_display_name"]:
            view.requester = RequesterSummary(
                email=row["requester_email"],
                display_name=row["requester_display_name"],
            )
        return view


store = PostgresNeedexStore(get_settings().taskview_database_url)
