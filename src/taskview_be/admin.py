from datetime import UTC, datetime

from .admin_schemas import (
    UiAccountPayload,
    UiAccountSession,
    UiApprovalInbox,
    UiApprovalRequest,
    UiAuditEvent,
    UiCatalogField,
    UiDataSourceDetail,
    UiDataSourcesPayload,
    UiDataSourceStats,
    UiDataSourceSummary,
    UiIntegrationSettings,
    UiPolicySettings,
    UiTeamMember,
    UiWorkspaceNotifications,
    UiWorkspaceSettings,
)
from .auth_schemas import UserPublic
from .experience import DATA_SOURCES, build_approval_review, task_view_name
from .experience_schemas import AuditEvent
from .schemas import NeedexResponse
from .store import WorkspaceApiKeyRecord, WorkspaceDataSourceRecord
from .workspace_schemas import WorkspaceMember, WorkspacePublic

PII_LEVEL = {"product": "LOW", "operations": "MEDIUM", "voc": "HIGH"}
ORGANIZATION = {"product": "FCC", "operations": "NYC Open Data", "voc": "NHTSA"}
ACTIVE_VIEWS = {"product": 5, "operations": 7, "voc": 4}
LAST_SYNC = {"product": "12분 전", "operations": "8분 전", "voc": "5분 전"}


def build_data_sources_overview(
    active_view_count: int,
    workspace_sources: list[WorkspaceDataSourceRecord] | None = None,
    public_snapshots: list[dict[str, object]] | None = None,
) -> UiDataSourcesPayload:
    workspace_sources = workspace_sources or []
    snapshot_by_key = {str(item["source_key"]): item for item in public_snapshots or []}
    sources = [
        UiDataSourceSummary(
            id=source.id.removeprefix("src_").replace("_", "-"),
            flag=source.country_flag,
            name=source.name,
            organization=ORGANIZATION[source.key],
            region=source.region.replace("Ho Chi Minh City", "HCMC"),
            pii=PII_LEVEL[source.key],
            engine="Official API → PostgreSQL",
            schema=" · ".join(source.datasets),
            views=ACTIVE_VIEWS[source.key],
            lastSync=(
                snapshot_by_key[source.key]["fetched_at"]
                .astimezone(UTC)
                .strftime("%Y-%m-%d %H:%M UTC")
                if source.key in snapshot_by_key
                else "동기화 필요"
            ),
            sourceType="public-live",
            rowCount=int(snapshot_by_key.get(source.key, {}).get("row_count") or 0),
            officialUrl=source.official_url,
        )
        for source in DATA_SOURCES
    ]
    for source in workspace_sources:
        catalog_names = [
            f"{table.get('schema', 'public')}.{table.get('name', 'table')}"
            for table in source.catalog[:3]
        ]
        sources.append(
            UiDataSourceSummary(
                id=source.id,
                flag="🗄️",
                name=source.name,
                organization=source.organization,
                region=source.region,
                pii="HIGH" if source.sensitive_field_count else "LOW",
                engine=source.engine,
                schema=" · ".join(catalog_names) or "metadata catalog",
                views=0,
                lastSync="방금 전",
                sourceType="workspace",
            )
        )
    built_in_fields = sum(len(source.fields) for source in DATA_SOURCES)
    built_in_pii = sum(
        field.privacy_class in {"direct_identifier", "sensitive"}
        for source in DATA_SOURCES
        for field in source.fields
    )
    return UiDataSourcesPayload(
        sources=sources,
        stats=UiDataSourceStats(
            connected=len(sources),
            builtIn=len(DATA_SOURCES),
            workspaceConnected=len(workspace_sources),
            fields=built_in_fields + sum(source.field_count for source in workspace_sources),
            pii=built_in_pii + sum(source.sensitive_field_count for source in workspace_sources),
            activeViews=active_view_count,
        ),
    )


def build_data_source_detail(source_id: str) -> UiDataSourceDetail | None:
    normalized = source_id.replace("-", "_")
    legacy_aliases = {
        "seoul_product": "product",
        "tokyo_operations": "operations",
        "hcmc_cs": "voc",
    }
    normalized = legacy_aliases.get(normalized, normalized)
    source = next(
        (item for item in DATA_SOURCES if normalized in {item.id.removeprefix("src_"), item.key}),
        None,
    )
    if source is None:
        return None
    sensitivity = {
        "non_sensitive": "LOW",
        "quasi_identifier": "MEDIUM",
        "direct_identifier": "HIGH",
        "sensitive": "HIGH",
    }
    transform = {
        "select": "SELECT",
        "generalize": "GENERALIZE",
        "bucket": "BUCKET",
        "drop": "DROP",
        "mask": "TOKENIZE",
        "extract_category": "CATEGORY",
        "aggregate": "AGGREGATE",
    }
    fields = [
        UiCatalogField(
            field=field.name,
            meaning=field.name.replace("_", " ").title(),
            sensitivity=sensitivity[field.privacy_class],
            transform=transform[field.allowed_transforms[0]],
        )
        for field in source.fields[:8]
    ]
    return UiDataSourceDetail(
        name=source.name,
        flag=source.country_flag,
        subtitle=f"{ORGANIZATION[source.key]} · {source.region} · {source.country_code} · PostgreSQL",
        owner=source.owner,
        region=f"{source.region} ({source.country_code})",
        fields=fields,
        sourceType="public-live",
    )


def build_workspace_data_source_detail(
    source: WorkspaceDataSourceRecord,
) -> UiDataSourceDetail:
    fields: list[UiCatalogField] = []
    for table in source.catalog:
        table_name = str(table.get("name", "table"))
        schema_name = str(table.get("schema", "public"))
        table_fields = table.get("fields", [])
        if not isinstance(table_fields, list):
            continue
        for field in table_fields:
            if not isinstance(field, dict):
                continue
            sensitive = bool(field.get("sensitive_name", False))
            fields.append(
                UiCatalogField(
                    field=str(field.get("name", "field")),
                    meaning=(f"{schema_name}.{table_name} · {field.get('data_type', 'unknown')}"),
                    sensitivity="HIGH" if sensitive else "LOW",
                    transform="DROP" if sensitive else "SELECT",
                )
            )
    return UiDataSourceDetail(
        name=source.name,
        flag="🗄️",
        subtitle=f"{source.organization} · {source.region} · {source.engine}",
        owner=source.owner,
        region=source.region,
        fields=fields[:100],
        sourceType="workspace",
    )


def build_approval_inbox(views: list[NeedexResponse], owner: UserPublic) -> UiApprovalInbox:
    items: list[UiApprovalRequest] = []
    for view in views[:20]:
        review = build_approval_review(view, owner)
        if view.status == "approved":
            risk = "APPROVED"
            state = "approved"
        elif review.risk_level == "high":
            risk = "HIGH RISK"
            state = "pending"
        elif view.status == "rejected":
            risk = "REVIEW"
            state = "rejected"
        else:
            risk = "REVIEW"
            state = "pending"
        transforms = [
            f"{change.before} → {change.after}"
            for change in review.recommended_alternative.changes[:3]
        ]
        if not transforms:
            transforms = [
                f"{item.input_fields[0]} → {item.output_field}"
                for item in view.plan.transformations[:2]
                if item.input_fields
            ]
        items.append(
            UiApprovalRequest(
                id=review.request_id,
                risk=risk,
                title=review.view_name.replace("_", " ").title(),
                requester=review.requester or "Product Team · Seoul",
                owner=review.assigned_owner,
                transform=" · ".join(transforms) or "Purpose scope review",
                finding=review.reasons[0].title if review.reasons else "신규 목적 검토",
                state=state,
            )
        )
    return UiApprovalInbox(
        pending=sum(item.state == "pending" for item in items),
        highRisk=sum(item.risk == "HIGH RISK" for item in items),
        approved=sum(item.state == "approved" for item in items),
        items=items,
    )


def build_audit_ui(
    views: list[NeedexResponse], events_by_view: dict[str, list[AuditEvent]]
) -> list[UiAuditEvent]:
    view_by_id = {view.id: view for view in views}
    output: list[tuple[datetime, UiAuditEvent]] = []
    mapping = {
        "created": ("VIEW_CREATED", "PASS", "success"),
        "refined": ("VIEW_COMPILED", "PASS", "success"),
        "submitted": ("APPROVAL_REQUESTED", "REVIEW", "primary"),
        "approved": ("APPROVED", "PASS", "success"),
        "approved_alternative": ("APPROVED", "SAFE ALT", "safe"),
        "rejected": ("POLICY_CHECK", "DENY", "danger"),
        "downloaded": ("DATA_DOWNLOADED", "PASS", "success"),
    }
    for view_id, events in events_by_view.items():
        view = view_by_id[view_id]
        for event in events:
            name, result, tone = mapping[event.action]
            evidence = (
                view.evidence if event.action in {"approved", "approved_alternative"} else None
            )
            evidence_id = evidence.view_id if evidence else None
            output.append(
                (
                    event.created_at,
                    UiAuditEvent(
                        time=event.created_at.astimezone(UTC).strftime("%H:%M:%S"),
                        event=name,
                        view=task_view_name(view),
                        purpose=view.purpose,
                        actor=event.actor_email or "System",
                        result=result,
                        tone=tone,
                        evidence=f"Contract #{evidence_id}" if evidence_id else None,
                        evidenceId=evidence_id,
                        evidenceHash=evidence.content_sha256 if evidence else None,
                    ),
                )
            )
    return [item for _, item in sorted(output, key=lambda pair: pair[0], reverse=True)[:100]]


def build_workspace_ui(workspace: WorkspacePublic) -> UiWorkspaceSettings:
    region_labels = {
        "KR-11": "Seoul · KR",
        "JP-13": "Tokyo · JP",
        "VN-SG": "HCMC · VN",
        "GLOBAL": "Global",
    }
    output_labels = {
        "dashboard": "Dashboard",
        "api": "API",
        "dashboard_api": "Dashboard + API",
    }
    return UiWorkspaceSettings(
        name=workspace.name,
        region=region_labels[workspace.region],
        ttl=f"{workspace.default_ttl_days}일",
        output=output_labels[workspace.default_output_mode],
        notifications=UiWorkspaceNotifications(
            approval=workspace.notifications.approval_requested,
            approved=workspace.notifications.view_approved,
            expiry=workspace.notifications.ttl_expiring,
            audit=workspace.notifications.audit_events,
        ),
    )


def default_policy_ui() -> UiPolicySettings:
    return UiPolicySettings(
        newPurpose=True,
        highRisk=True,
        lowRisk=False,
        refinement=True,
        cumulative=True,
        block=True,
    )


def build_team_ui(members: list[WorkspaceMember]) -> list[UiTeamMember]:
    labels = {
        "requester": "Product / UX",
        "data_owner": "Data Owner",
        "admin": "Security / Admin",
    }
    return [
        UiTeamMember(
            id=member.id,
            initial=member.display_name[:1].upper(),
            name=member.display_name,
            email=member.email,
            role=labels[member.role],
            region=member.region,
        )
        for member in members
    ]


def build_integrations_ui(api_key: WorkspaceApiKeyRecord | None) -> UiIntegrationSettings:
    if api_key is None:
        return UiIntegrationSettings(keyMasked="", lastUsed="", webhooks=[])
    if api_key.last_used_at is None:
        last_used = "아직 사용 안 함"
    else:
        last_used = api_key.last_used_at.astimezone(UTC).strftime("%Y.%m.%d %H:%M UTC")
    return UiIntegrationSettings(
        keyMasked=f"{api_key.key_prefix}{'•' * 12}",
        lastUsed=last_used,
        webhooks=[],
    )


def build_account_ui(user: UserPublic) -> UiAccountPayload:
    return UiAccountPayload(
        name=user.display_name,
        email=user.email,
        verified=user.email_verified,
        passwordChanged="최근 변경",
        sessions=[
            UiAccountSession(
                id="current",
                name="현재 세션",
                device="현재 브라우저 · Seoul",
                when="지금",
                current=True,
            )
        ],
    )
