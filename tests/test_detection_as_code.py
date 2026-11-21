"""Tests for Detection-as-Code engine, rule lifecycle, and triage automation."""

import pytest
from cloudposture.detection_engine import (
    DetectionEngine,
    DetectionRule,
    DetectionSeverity,
    MitreAttack,
    RuleLifecycle,
    RuleTestCase,
    build_anomalous_iam_assume_role_rule,
    build_aws_console_login_without_mfa_rule,
)
from cloudposture.triage_automation import AlertTriagePipeline, TriageContext


def test_rule_registration_and_retrieval():
    engine = DetectionEngine()
    rule = build_aws_console_login_without_mfa_rule()
    engine.register_rule(rule)

    assert engine.get_rule(rule.rule_id) == rule
    assert len(engine.list_rules()) == 1
    assert len(engine.list_rules(RuleLifecycle.PRODUCTION)) == 1
    assert len(engine.list_rules(RuleLifecycle.EXPERIMENTAL)) == 0

    with pytest.raises(ValueError, match="already registered"):
        engine.register_rule(rule)


def test_rule_test_harness_success():
    engine = DetectionEngine()
    rule1 = build_aws_console_login_without_mfa_rule()
    rule2 = build_anomalous_iam_assume_role_rule()
    engine.register_rule(rule1)
    engine.register_rule(rule2)

    assert engine.test_rule_harness(rule1.rule_id) == []
    assert engine.test_rule_harness(rule2.rule_id) == []


def test_rule_promotion_blocks_on_failing_tests():
    engine = DetectionEngine()
    # Create an experimental rule with broken test assertion
    failing_rule = DetectionRule(
        rule_id="DET-TEST-FAIL",
        name="Always True Broken Rule",
        description="Fails negative test",
        severity=DetectionSeverity.LOW,
        lifecycle=RuleLifecycle.EXPERIMENTAL,
        mitre=MitreAttack("Discovery", "T1087", "Account Discovery"),
        evaluator=lambda e: True,  # Always returns True
        extract_entity=lambda e: "test",
        extract_evidence=lambda e: {},
        test_cases=[
            RuleTestCase(name="Should not match", event={"type": "safe"}, should_match=False)
        ],
    )
    engine.register_rule(failing_rule)

    failures = engine.test_rule_harness("DET-TEST-FAIL")
    assert len(failures) == 1
    assert "expected match=False, got match=True" in failures[0]

    with pytest.raises(RuntimeError, match="Cannot promote rule DET-TEST-FAIL to production"):
        engine.promote_rule("DET-TEST-FAIL", RuleLifecycle.PRODUCTION)


def test_evaluate_event_unsuppressed_alert():
    engine = DetectionEngine()
    engine.register_rule(build_aws_console_login_without_mfa_rule())

    event = {
        "event_id": "evt-1001",
        "timestamp": "2026-11-21T10:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
        "userIdentity": {"userName": "admin-bob", "arn": "arn:aws:iam::111122223333:user/admin-bob"},
        "sourceIPAddress": "198.51.100.99",
        "userAgent": "Mozilla/5.0",
    }

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.rule_id == "DET-AWS-001"
    assert alt.severity == DetectionSeverity.HIGH
    assert alt.entity_id == "arn:aws:iam::111122223333:user/admin-bob"
    assert not alt.suppressed
    assert alt.mitre.technique_id == "T1078.004"


def test_evaluate_event_suppressed_by_filter():
    engine = DetectionEngine()
    engine.register_rule(build_aws_console_login_without_mfa_rule())

    # Source IP is the jumpbox (10.0.99.1)
    event = {
        "event_id": "evt-1002",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
        "userIdentity": {"userName": "ops-bot", "arn": "arn:aws:iam::111122223333:user/ops-bot"},
        "sourceIPAddress": "10.0.99.1",
    }

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.suppressed is True
    assert "jumpbox maintenance" in alt.suppression_reason


def test_anomalous_iam_role_assumption_alert():
    engine = DetectionEngine()
    engine.register_rule(build_anomalous_iam_assume_role_rule())

    event = {
        "event_id": "evt-2001",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/Production-AdminRole"},
        "userIdentity": {"arn": "arn:aws:iam::999999999999:user/compromised-user"},
        "sourceIPAddress": "185.220.101.5",
    }

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    alt = alerts[0]
    assert alt.rule_id == "DET-AWS-002"
    assert alt.severity == DetectionSeverity.CRITICAL
    assert alt.mitre.tactic == "Privilege Escalation"
    assert "arn:aws:iam::123456789012:role/Production-AdminRole" == alt.entity_id


def test_staging_rule_exclusion_unless_requested():
    engine = DetectionEngine()
    rule = build_anomalous_iam_assume_role_rule()
    rule.lifecycle = RuleLifecycle.STAGING
    engine.register_rule(rule)

    event = {
        "event_id": "evt-3001",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/Admin"},
        "sourceIPAddress": "203.0.113.1",
    }

    # In production evaluation mode, staging rules do not fire
    assert engine.evaluate_event(event, include_staging=False) == []
    # In staging/shadow mode, alerts are captured
    staging_alerts = engine.evaluate_event(event, include_staging=True)
    assert len(staging_alerts) == 1


def test_alert_triage_enrichment_and_containment():
    engine = DetectionEngine()
    rule = build_anomalous_iam_assume_role_rule()
    engine.register_rule(rule)

    event = {
        "event_id": "evt-4001",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "requestParameters": {"roleArn": "arn:aws:iam::123:role/prod-admin-role"},
        "sourceIPAddress": "203.0.113.55",
    }
    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    alert = alerts[0]

    pipeline = AlertTriagePipeline()

    # Pass 4 historical alerts for velocity check and correlated posture finding
    historical = [alert, alert, alert, alert]
    posture_findings = [{"resource_id": "prod-admin-role", "rule_id": "IAM_OVERPRIVILEGED"}]

    enriched = pipeline.enrich_alert(alert, historical_alerts=historical, posture_findings=posture_findings)

    assert enriched.context.asset_criticality == "mission_critical"
    assert enriched.context.recent_alert_count == 4
    assert len(enriched.context.correlated_posture_findings) == 1
    assert enriched.risk_score >= 90.0
    assert any("Revoke all active STS sessions" in act for act in enriched.recommended_actions)
    assert any("Escalate to Tier 2" in act for act in enriched.recommended_actions)
    assert "ALERT TRIAGE:" in enriched.investigation_summary


def test_llm_custom_investigation_hook():
    engine = DetectionEngine()
    rule = build_aws_console_login_without_mfa_rule()
    engine.register_rule(rule)

    event = {
        "event_id": "evt-5001",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
        "userIdentity": {"arn": "arn:aws:iam::123:user/test-dev"},
        "sourceIPAddress": "198.51.100.1",
    }
    alerts = engine.evaluate_event(event)
    alert = alerts[0]

    def mock_llm_analyzer(alt, ctx):
        return f"SYNTHESIZED THREAT: Principal {ctx.entity_id} breached MFA perimeter."

    pipeline = AlertTriagePipeline(llm_analyzer=mock_llm_analyzer)
    enriched = pipeline.enrich_alert(alert, historical_alerts=[])

    assert "SYNTHESIZED THREAT: Principal arn:aws:iam::123:user/test-dev breached MFA perimeter." in enriched.investigation_summary
