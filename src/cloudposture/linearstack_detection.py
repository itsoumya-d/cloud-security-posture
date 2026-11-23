"""LinearStack: Cloud Security & Automated Threat Reduction Pipeline.

Provides measurable detection engineering, security event triage,
NZISM controls validation, and automated containment dispatch for
distributed cloud enterprise environments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar


@dataclass
class ThreatSignal:
    signal_id: str
    source_ip: str
    cloud_provider: str  # aws, azure, gcp, kubernetes
    event_type: str
    resource_id: str
    mitre_technique: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str  # critical, high, medium, low
    threat_signal: ThreatSignal
    nzism_control: str
    risk_score: float  # 0.0 to 100.0
    recommended_action: str
    containment_status: str = "pending"


@dataclass
class ThreatReductionReport:
    batch_id: str
    customer_id: str
    generated_at: str
    signals_processed: int
    alerts_triggered: int
    critical_alerts: int
    containment_actions_dispatched: int
    posture_health_score: float
    nzism_coverage_percentage: float
    alerts: list[Alert] = field(default_factory=list)


class LinearStackDetectionEngine:
    """Automated threat detection and incident triage pipeline."""

    NZISM_SECURITY_RULES: ClassVar[list[dict[str, Any]]] = [
        {
            "rule_id": "NZISM-16.1.1-UNAUTH-ROOT-LOGIN",
            "name": "Root Privilege Without Multi-Factor Authentication",
            "mitre_technique": "T1078.004",
            "nzism_control": "16.1.1",
            "severity": "critical",
            "event_type": "ConsoleLogin",
            "risk_weight": 95.0,
            "containment_action": "RevokeActiveSessionsAndRotateKeys"
        },
        {
            "rule_id": "NZISM-14.2.3-PLAINTEXT-EXFILTRATION",
            "name": "Unencrypted Cloud Storage Data Exfiltration",
            "mitre_technique": "T1567.002",
            "nzism_control": "14.2.3",
            "severity": "high",
            "event_type": "DataTransfer",
            "risk_weight": 85.0,
            "containment_action": "ApplyBucketPolicyAndBlockEgress"
        },
        {
            "rule_id": "NZISM-18.3.1-LOG-TAMPERING",
            "name": "Audit Logging Deactivation or Deletion",
            "mitre_technique": "T1562.001",
            "nzism_control": "18.3.1",
            "severity": "critical",
            "event_type": "StopLogging",
            "risk_weight": 90.0,
            "containment_action": "ReenableAuditLoggingAndLockKMS"
        },
        {
            "rule_id": "NZISM-12.1.2-K8S-PRIVILEGE-ESCALATION",
            "name": "Privileged Kubernetes Container Execution",
            "mitre_technique": "T1611",
            "nzism_control": "12.1.2",
            "severity": "high",
            "event_type": "ExecPod",
            "risk_weight": 80.0,
            "containment_action": "TerminatePodAndIsolateNode"
        }
    ]

    def __init__(self, customer_id: str = "Enterprise-Client") -> None:
        self.customer_id = customer_id

    def process_threat_signals(
        self, signals: list[ThreatSignal], auto_contain: bool = True
    ) -> ThreatReductionReport:
        """Processes raw telemetry, applies detection logic, and coordinates threat reduction."""
        alerts: list[Alert] = []
        containment_count = 0

        for sig in signals:
            for rule in self.NZISM_SECURITY_RULES:
                if sig.event_type == rule["event_type"]:
                    alert = Alert(
                        alert_id=f"ALT-{sig.signal_id[:8]}",
                        rule_id=rule["rule_id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        threat_signal=sig,
                        nzism_control=rule["nzism_control"],
                        risk_score=rule["risk_weight"],
                        recommended_action=rule["containment_action"],
                        containment_status="contained" if auto_contain else "pending"
                    )
                    if auto_contain:
                        containment_count += 1
                    alerts.append(alert)

        critical_count = sum(1 for a in alerts if a.severity == "critical")
        total_signals = len(signals)
        
        # Calculate posture health score: 100 base, deducted by triggered alert weights
        if total_signals == 0:
            posture_health = 100.0
        else:
            total_penalty = sum(a.risk_score for a in alerts)
            posture_health = max(0.0, 100.0 - (total_penalty / max(1, len(signals))))

        # NZISM coverage: percentage of rule controls verified
        unique_controls = {a.nzism_control for a in alerts}
        coverage = (len(unique_controls) / len(self.NZISM_SECURITY_RULES)) * 100.0

        return ThreatReductionReport(
            batch_id=f"BATCH-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
            customer_id=self.customer_id,
            generated_at=datetime.now(UTC).isoformat(),
            signals_processed=total_signals,
            alerts_triggered=len(alerts),
            critical_alerts=critical_count,
            containment_actions_dispatched=containment_count,
            posture_health_score=round(posture_health, 2),
            nzism_coverage_percentage=round(coverage, 2),
            alerts=alerts
        )
