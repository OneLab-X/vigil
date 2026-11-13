"""Output contracts (mirrors packages/core/src/investigation/contract.ts; the control plane re-validates)."""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceItem(_Strict):
    event_id: str = Field(pattern=r"^[0-9a-f-]{36}$", description="UUID of an event returned by a tool in THIS run")
    claim: str = Field(min_length=3, max_length=2000)
    cited_fields: dict[str, str | int | None] | None = Field(
        default=None,
        description="Optional exact field values from the event (source_ip, destination_ip, principal, resource_id, action, status, http_status, url_path, event_timestamp). Each is verified.",
    )


class TimelineItem(_Strict):
    timestamp: str
    description: str = Field(max_length=1000)
    event_id: str | None = None


class Entities(_Strict):
    ips: list[str] = []
    principals: list[str] = []
    resources: list[str] = []


class Impact(_Strict):
    outcome: Literal["succeeded", "failed", "blocked", "unknown"]
    scope: str = Field(max_length=2000)
    data_exposure: Literal["none_observed", "possible", "confirmed", "unknown"]


class Recommendation(_Strict):
    action: str = Field(max_length=500)
    rationale: str = Field(max_length=2000)
    priority: Literal["low", "medium", "high", "urgent"]


class InvestigationContract(_Strict):
    case_id: str = Field(pattern=r"^CASE-\d{4,}$")
    verdict: Literal["confirmed", "likely", "benign", "inconclusive", "needs_more_data"]
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    summary: str = Field(min_length=10, max_length=6000)
    timeline: list[TimelineItem] = Field(max_length=200)
    entities: Entities
    evidence: list[EvidenceItem] = Field(max_length=100)
    contradictory_evidence: list[EvidenceItem] = Field(max_length=100)
    impact_assessment: Impact
    recommended_actions: list[Recommendation] = Field(max_length=20)
    requires_human_approval: Literal[True]
    abstention_reason: str | None = None


class TriageOutput(_Strict):
    should_investigate: bool
    rationale: str = Field(min_length=5, max_length=4000)
    priority: Literal["low", "medium", "high", "urgent"]
    related_event_ids: list[str] = Field(default_factory=list, max_length=100)
    unexplained_patterns: list[str] = Field(default_factory=list, max_length=20)


OUTPUT_MODEL = {"detection_analyst": TriageOutput, "investigation_analyst": InvestigationContract}
