"""Unit tests for LinearStack detection and threat reduction engine."""
from __future__ import annotations

from cloudposture.linearstack_detection import (
    LinearStackDetectionEngine,
    ThreatReductionReport,
    ThreatSignal,
)


def test_engine_initialization() -> None:
    engine = LinearStackDetectionEngine(customer_id="Test-Corp")
    assert engine.customer_id == "Test-Corp"
    assert len(engine.NZISM_SECURITY_RULES) == 4


def test_process_threat_signals_empty() -> None:
    engine = LinearStackDetectionEngine(customer_id="Acme-NZ")
    report = engine.process_threat_signals([])

    assert isinstance(report, ThreatReductionReport)
    assert report.signals_processed == 0
    assert report.alerts_triggered == 0
    assert report.critical_alerts == 0
    assert report.posture_health_score == 100.0
    assert report.nzism_coverage_percentage == 0.0
    assert len(report.alerts) == 0


def test_process_root_login_critical_alert() -> None:
    engine = LinearStackDetectionEngine(customer_id="FinTech-Auckland")
    sig = ThreatSignal(
        signal_id="sig-001-root",
        source_ip="203.0.113.42",
        cloud_provider="aws",
        event_type="ConsoleLogin",
        resource_id="arn:aws:iam::123456789012:root",
        mitre_technique="T1078.004",
        payload={"MFAUsed": "No"}
    )

    report = engine.process_threat_signals([sig], auto_contain=True)

    assert report.signals_processed == 1
    assert report.alerts_triggered == 1
    assert report.critical_alerts == 1
    assert report.containment_actions_dispatched == 1
    assert report.alerts[0].severity == "critical"
    assert report.alerts[0].nzism_control == "16.1.1"
    assert report.alerts[0].containment_status == "contained"
    assert report.alerts[0].recommended_action == "RevokeActiveSessionsAndRotateKeys"


def test_process_multiple_signals_and_posture_calculation() -> None:
    engine = LinearStackDetectionEngine(customer_id="Enterprise-Cloud")
    signals = [
        ThreatSignal(
            signal_id="sig-002-data",
            source_ip="198.51.100.10",
            cloud_provider="azure",
            event_type="DataTransfer",
            resource_id="storage-account-finance",
            mitre_technique="T1567.002"
        ),
        ThreatSignal(
            signal_id="sig-003-logging",
            source_ip="192.0.2.55",
            cloud_provider="gcp",
            event_type="StopLogging",
            resource_id="projects/audit-cloud/logSinks/security",
            mitre_technique="T1562.001"
        ),
        ThreatSignal(
            signal_id="sig-004-benign",
            source_ip="10.0.0.1",
            cloud_provider="kubernetes",
            event_type="ListPods",
            resource_id="kube-system",
            mitre_technique=""
        )
    ]

    report = engine.process_threat_signals(signals, auto_contain=False)

    assert report.signals_processed == 3
    assert report.alerts_triggered == 2
    assert report.critical_alerts == 1  # StopLogging is critical
    assert report.containment_actions_dispatched == 0  # auto_contain is False
    assert report.nzism_coverage_percentage == 50.0  # 2 of 4 rules triggered
    assert report.posture_health_score < 100.0


def test_kubernetes_privilege_escalation_detection() -> None:
    engine = LinearStackDetectionEngine(customer_id="K8s-Prod")
    sig = ThreatSignal(
        signal_id="sig-005-k8s",
        source_ip="172.16.0.4",
        cloud_provider="kubernetes",
        event_type="ExecPod",
        resource_id="production/payment-gateway-7f9",
        mitre_technique="T1611"
    )

    report = engine.process_threat_signals([sig], auto_contain=True)

    assert report.alerts_triggered == 1
    assert report.alerts[0].nzism_control == "12.1.2"
    assert report.alerts[0].recommended_action == "TerminatePodAndIsolateNode"
    assert report.alerts[0].containment_status == "contained"
