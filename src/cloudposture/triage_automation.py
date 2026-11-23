"""Automated triage, enrichment, and LLM-assisted investigation workflows.

Aggregates entity telemetry, correlates historical alerts and posture findings,
and produces structured investigation briefings and containment recommendations.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cloudposture.detection_engine import DetectionAlert, DetectionSeverity


@dataclass
class TriageContext:
    entity_id: str
    asset_criticality: str  # low, medium, high, mission_critical
    recent_alert_count: int
    correlated_posture_findings: list[str]
    threat_intel_tags: list[str] = field(default_factory=list)


@dataclass
class EnrichedAlert:
    alert: DetectionAlert
    context: TriageContext
    risk_score: float  # 0.0 to 100.0
    investigation_summary: str
    recommended_actions: list[str]
    triaged_at: str


class AlertTriagePipeline:
    """Pipelines alerts through enrichment, scoring, and investigation synthesis."""

    def __init__(
        self,
        llm_analyzer: Callable[[DetectionAlert, TriageContext], str] | None = None,
    ) -> None:
        self.llm_analyzer = llm_analyzer

    def enrich_alert(
        self,
        alert: DetectionAlert,
        historical_alerts: list[DetectionAlert],
        posture_findings: list[dict[str, Any]] | None = None,
    ) -> EnrichedAlert:
        """Enriches an alert with entity velocity, posture correlation, and threat scores."""
        entity = alert.entity_id

        # Calculate entity alert velocity (alerts on this entity in history)
        entity_alerts = [a for a in historical_alerts if a.entity_id == entity and not a.suppressed]
        recent_count = len(entity_alerts)

        # Correlate with static posture findings
        correlated_findings: list[str] = []
        if posture_findings:
            for f in posture_findings:
                res_id = str(f.get("resource_id", ""))
                rule_id = str(f.get("rule_id", ""))
                if res_id in entity or entity in res_id:
                    correlated_findings.append(f"{rule_id}:{res_id}")

        # Determine asset criticality
        criticality = "medium"
        entity_lower = entity.lower()
        if any(k in entity_lower for k in ["admin", "root", "prod", "prod-cluster", "billing"]):
            criticality = "mission_critical"
        elif any(k in entity_lower for k in ["staging", "dev", "test"]):
            criticality = "low"

        # Calculate aggregate composite risk score (0-100)
        base_scores = {
            DetectionSeverity.LOW: 25.0,
            DetectionSeverity.MEDIUM: 50.0,
            DetectionSeverity.HIGH: 75.0,
            DetectionSeverity.CRITICAL: 90.0,
        }
        score = base_scores.get(alert.severity, 50.0)

        # Multipliers for criticality & burst velocity
        if criticality == "mission_critical":
            score = min(100.0, score * 1.15)
        if recent_count > 3:
            score = min(100.0, score + 10.0)
        if correlated_findings:
            score = min(100.0, score + 5.0)

        threat_tags = []
        if alert.mitre.tactic:
            threat_tags.append(f"mitre:{alert.mitre.tactic.lower().replace(' ', '_')}")
        if recent_count > 5:
            threat_tags.append("behavior:high_velocity_anomaly")

        context = TriageContext(
            entity_id=entity,
            asset_criticality=criticality,
            recent_alert_count=recent_count,
            correlated_posture_findings=correlated_findings,
            threat_intel_tags=threat_tags,
        )

        # Produce investigation summary and containment actions
        summary, actions = self._synthesize_investigation(alert, context)

        return EnrichedAlert(
            alert=alert,
            context=context,
            risk_score=round(score, 1),
            investigation_summary=summary,
            recommended_actions=actions,
            triaged_at=datetime.now(UTC).isoformat(),
        )

    def _synthesize_investigation(
        self, alert: DetectionAlert, context: TriageContext
    ) -> tuple[str, list[str]]:
        """Generates investigation summary and containment runbook items."""
        if self.llm_analyzer:
            try:
                custom_summary = self.llm_analyzer(alert, context)
                if custom_summary:
                    return custom_summary, self._generate_containment_actions(alert, context)
            except Exception:
                pass

        # Deterministic structured synthesis engine
        summary_lines = [
            f"ALERT TRIAGE: {alert.rule_name} (Severity: {alert.severity.value.upper()})",
            f"Target Entity: {context.entity_id} [Criticality: {context.asset_criticality}]",
            f"MITRE ATT&CK: {alert.mitre.technique_id} - {alert.mitre.technique_name} ({alert.mitre.tactic})",
            f"Entity Velocity: {context.recent_alert_count} prior unsuppressed alerts recorded for this identity.",
        ]

        if context.correlated_posture_findings:
            summary_lines.append(
                f"Correlated Vulnerabilities: {len(context.correlated_posture_findings)} open posture findings."
            )

        summary = "\n".join(summary_lines)
        actions = self._generate_containment_actions(alert, context)
        return summary, actions

    def _generate_containment_actions(
        self, alert: DetectionAlert, context: TriageContext
    ) -> list[str]:
        actions = []
        if alert.severity in (DetectionSeverity.HIGH, DetectionSeverity.CRITICAL):
            actions.append(f"Revoke all active STS sessions and refresh tokens for principal '{context.entity_id}'")
            actions.append("Enforce step-up MFA or temporary session suspension on target cloud account")
        else:
            actions.append(f"Notify principal '{context.entity_id}' to verify recent activity authorization")

        if "Credential Access" in alert.mitre.tactic:
            actions.append("Rotate access keys and credentials associated with entity")

        if context.recent_alert_count > 3:
            actions.append("Escalate to Tier 2 Security Operations for lateral movement analysis")

        return actions
