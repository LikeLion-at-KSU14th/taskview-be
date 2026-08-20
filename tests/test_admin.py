from datetime import UTC, datetime, timedelta

from taskview_be.admin import build_audit_ui
from taskview_be.experience_schemas import AuditEvent
from taskview_be.materializer import create_evidence, preview_rows
from taskview_be.schemas import (
    NeedexResponse,
    PolicyFinding,
    PurposeSpec,
    TransformPlanItem,
    UtilityReport,
    ViewPlan,
)


def approved_view() -> NeedexResponse:
    plan = ViewPlan(
        purpose_spec=PurposeSpec(
            objective="주간 가입 이탈을 비교한다",
            decision_to_support="개선 우선순위를 정한다",
            audience="product",
            requested_fields=["event_time"],
        ),
        selected_sources=["product"],
        transformations=[
            TransformPlanItem(
                source="product",
                input_fields=["event_time"],
                output_field="week",
                transformation="aggregate",
                rationale="개별 시각 대신 주 단위만 유지",
            )
        ],
        preview_columns=["week", "case_count"],
    )
    view = NeedexResponse(
        id="tv_evidence_contract",
        status="approved",
        purpose="주간 가입 이탈을 비교해 개선 우선순위를 정한다",
        audience="product",
        ttl_days=7,
        plan=plan,
        policy_findings=[
            PolicyFinding(
                code="POLICY_READY",
                severity="info",
                message="정책 기준을 충족했습니다.",
                action="승인을 요청하세요.",
            )
        ],
        utility=UtilityReport(
            selected_field_count=2,
            removed_field_count=0,
            estimated_rows=4,
            utility_score=90,
        ),
        preview_rows=preview_rows(plan),
        created_at=datetime(2026, 8, 18, 2, 0, tzinfo=UTC),
        reviewed_by="owner@taskview.dev",
        review_reason="최소화 범위를 확인했습니다.",
    )
    view.evidence = create_evidence(view, "owner@taskview.dev")
    return view


def audit_event(*, event_id: int, action: str, created_at: datetime) -> AuditEvent:
    return AuditEvent(
        id=event_id,
        view_id="tv_evidence_contract",
        action=action,
        actor_email="owner@taskview.dev",
        from_status="proposed" if action == "approved" else None,
        to_status="approved" if action == "approved" else "proposed",
        reason=None,
        metadata={},
        created_at=created_at,
    )


def test_audit_ui_links_only_real_approval_evidence():
    view = approved_view()
    created_at = datetime(2026, 8, 18, 2, 0, tzinfo=UTC)
    events = [
        audit_event(event_id=1, action="created", created_at=created_at),
        audit_event(
            event_id=2,
            action="approved",
            created_at=created_at + timedelta(minutes=1),
        ),
    ]

    result = build_audit_ui([view], {view.id: events})
    by_event = {item.event: item for item in result}

    assert by_event["VIEW_CREATED"].evidence is None
    assert by_event["VIEW_CREATED"].evidenceId is None
    assert by_event["VIEW_CREATED"].evidenceHash is None
    assert by_event["APPROVED"].evidenceId == view.evidence.view_id
    assert by_event["APPROVED"].evidenceHash == view.evidence.content_sha256
    assert by_event["APPROVED"].evidence == f"Contract #{view.evidence.view_id}"


def test_audit_ui_does_not_invent_link_when_approval_has_no_contract():
    view = approved_view().model_copy(update={"evidence": None})
    event = audit_event(
        event_id=3,
        action="approved",
        created_at=datetime(2026, 8, 18, 2, 1, tzinfo=UTC),
    )

    [result] = build_audit_ui([view], {view.id: [event]})

    assert result.evidence is None
    assert result.evidenceId is None
    assert result.evidenceHash is None


def test_audit_ui_renders_download_events_without_evidence_links():
    view = approved_view()
    event = audit_event(
        event_id=4,
        action="downloaded",
        created_at=datetime(2026, 8, 18, 2, 2, tzinfo=UTC),
    )

    [result] = build_audit_ui([view], {view.id: [event]})

    assert result.event == "DATA_DOWNLOADED"
    assert result.result == "PASS"
    assert result.tone == "success"
    assert result.evidence is None
    assert result.evidenceId is None
    assert result.evidenceHash is None
