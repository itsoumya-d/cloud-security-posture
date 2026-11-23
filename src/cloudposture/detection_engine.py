"""Detection-as-Code engine for cloud and identity telemetry.

Provides rule lifecycle management, MITRE ATT&CK mapping, suppression logic,
and a deterministic test harness for verifying detection rules before production rollout.
"""
from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class DetectionSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleLifecycle(str, enum.Enum):
    EXPERIMENTAL = "experimental"
    STAGING = "staging"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"


@dataclass(frozen=True)
class MitreAttack:
    tactic: str
    technique_id: str
    technique_name: str


@dataclass
class RuleTestCase:
    name: str
    event: dict[str, Any]
    should_match: bool


@dataclass
class DetectionAlert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: DetectionSeverity
    mitre: MitreAttack
    event_id: str
    timestamp: str
    entity_id: str
    evidence: dict[str, Any]
    suppressed: bool = False
    suppression_reason: str | None = None


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: DetectionSeverity
    lifecycle: RuleLifecycle
    mitre: MitreAttack
    evaluator: Callable[[dict[str, Any]], bool]
    extract_entity: Callable[[dict[str, Any]], str]
    extract_evidence: Callable[[dict[str, Any]], dict[str, Any]]
    suppression_filters: list[Callable[[dict[str, Any]], str | None]] = field(default_factory=list)
    test_cases: list[RuleTestCase] = field(default_factory=list)


class DetectionEngine:
    """Detection-as-Code evaluation engine with rule lifecycle controls."""

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register_rule(self, rule: DetectionRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule {rule.rule_id} is already registered")
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        return self._rules.get(rule_id)

    def list_rules(self, lifecycle: RuleLifecycle | None = None) -> list[DetectionRule]:
        if lifecycle is None:
            return list(self._rules.values())
        return [r for r in self._rules.values() if r.lifecycle == lifecycle]

    def promote_rule(self, rule_id: str, new_lifecycle: RuleLifecycle) -> DetectionRule:
        rule = self._rules.get(rule_id)
        if not rule:
            raise KeyError(f"Rule {rule_id} not found")
        # Ensure tests pass before promoting to production
        if new_lifecycle == RuleLifecycle.PRODUCTION:
            failures = self.test_rule_harness(rule_id)
            if failures:
                raise RuntimeError(f"Cannot promote rule {rule_id} to production: test failures: {failures}")
        rule.lifecycle = new_lifecycle
        return rule

    def test_rule_harness(self, rule_id: str) -> list[str]:
        """Runs rule test cases verifying expected matches and true/false positive behavior."""
        rule = self._rules.get(rule_id)
        if not rule:
            raise KeyError(f"Rule {rule_id} not found")
        failures = []
        for tc in rule.test_cases:
            matched = rule.evaluator(tc.event)
            if matched != tc.should_match:
                failures.append(
                    f"Test '{tc.name}': expected match={tc.should_match}, got match={matched}"
                )
        return failures

    def evaluate_event(
        self, event: dict[str, Any], include_staging: bool = False
    ) -> list[DetectionAlert]:
        """Evaluates an event against registered active production/staging rules."""
        alerts: list[DetectionAlert] = []
        event_id = str(event.get("event_id") or event.get("id") or "evt-unknown")
        ts = str(event.get("timestamp") or datetime.now(UTC).isoformat())

        for rule in self._rules.values():
            if rule.lifecycle == RuleLifecycle.DEPRECATED or rule.lifecycle == RuleLifecycle.EXPERIMENTAL:
                continue
            if rule.lifecycle == RuleLifecycle.STAGING and not include_staging:
                continue

            try:
                if not rule.evaluator(event):
                    continue
            except Exception:
                # Malformed telemetry should fail safely without killing pipeline
                continue

            # Check suppressions
            suppressed = False
            suppression_reason = None
            for sup_filter in rule.suppression_filters:
                reason = sup_filter(event)
                if reason:
                    suppressed = True
                    suppression_reason = reason
                    break

            entity_id = rule.extract_entity(event)
            evidence = rule.extract_evidence(event)

            alert = DetectionAlert(
                alert_id=f"alt-{rule.rule_id}-{event_id}",
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                mitre=rule.mitre,
                event_id=event_id,
                timestamp=ts,
                entity_id=entity_id,
                evidence=evidence,
                suppressed=suppressed,
                suppression_reason=suppression_reason,
            )
            alerts.append(alert)

        return alerts


# --- Standard Built-in Detection Rules for Cloud Identity & Access ---


def build_aws_console_login_without_mfa_rule() -> DetectionRule:
    """Detects AWS Console logins without MFA on privileged accounts."""
    rule_id = "DET-AWS-001"
    name = "AWS Console Login Without MFA"
    desc = "Detects successful console login to AWS without multi-factor authentication."
    mitre = MitreAttack("Credential Access", "T1078.004", "Valid Accounts: Cloud Accounts")

    def evaluator(event: dict[str, Any]) -> bool:
        src = event.get("eventSource") == "signin.amazonaws.com"
        name = event.get("eventName") == "ConsoleLogin"
        status = event.get("responseElements", {}).get("ConsoleLogin") == "Success"
        mfa_used = event.get("additionalEventData", {}).get("MFAUsed") == "Yes"
        return src and name and status and not mfa_used

    def entity(event: dict[str, Any]) -> str:
        return event.get("userIdentity", {}).get("arn") or event.get("userIdentity", {}).get("userName") or "unknown"

    def evidence(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "source_ip": event.get("sourceIPAddress"),
            "user_agent": event.get("userAgent"),
            "user_identity": event.get("userIdentity"),
        }

    # Suppression: Allow internal jumpbox maintenance if specifically tagged
    def jumpbox_suppression(event: dict[str, Any]) -> str | None:
        if event.get("sourceIPAddress") == "10.0.99.1":
            return "Internal automation jumpbox maintenance window"
        return None

    test_cases = [
        RuleTestCase(
            name="Login without MFA should alert",
            event={
                "event_id": "test-1",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {"MFAUsed": "No"},
                "userIdentity": {"userName": "alice", "arn": "arn:aws:iam::123:user/alice"},
                "sourceIPAddress": "198.51.100.42",
            },
            should_match=True,
        ),
        RuleTestCase(
            name="Login with MFA should not alert",
            event={
                "event_id": "test-2",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {"MFAUsed": "Yes"},
                "userIdentity": {"userName": "alice", "arn": "arn:aws:iam::123:user/alice"},
                "sourceIPAddress": "198.51.100.42",
            },
            should_match=False,
        ),
    ]

    return DetectionRule(
        rule_id=rule_id,
        name=name,
        description=desc,
        severity=DetectionSeverity.HIGH,
        lifecycle=RuleLifecycle.PRODUCTION,
        mitre=mitre,
        evaluator=evaluator,
        extract_entity=entity,
        extract_evidence=evidence,
        suppression_filters=[jumpbox_suppression],
        test_cases=test_cases,
    )


def build_anomalous_iam_assume_role_rule() -> DetectionRule:
    """Detects STS AssumeRole from external untrusted IP or abnormal external account ID."""
    rule_id = "DET-AWS-002"
    name = "Cross-Account IAM Role Assumption from Anomalous Source"
    desc = "Detects STS AssumeRole invoked across accounts from external IP addresses."
    mitre = MitreAttack("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism")

    def evaluator(event: dict[str, Any]) -> bool:
        if event.get("eventSource") != "sts.amazonaws.com" or event.get("eventName") != "AssumeRole":
            return False
        request_params = event.get("requestParameters", {})
        target_role = request_params.get("roleArn", "")
        # Flag assumptions into administrator or security roles
        is_priv = any(k in target_role.lower() for k in ["admin", "security", "infra", "root"])
        ip = event.get("sourceIPAddress", "")
        is_external = not (ip.startswith(("10.", "172.16.", "192.168.")))
        return is_priv and is_external

    def entity(event: dict[str, Any]) -> str:
        return event.get("requestParameters", {}).get("roleArn") or "unknown-role"

    def evidence(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "target_role": event.get("requestParameters", {}).get("roleArn"),
            "caller_arn": event.get("userIdentity", {}).get("arn"),
            "source_ip": event.get("sourceIPAddress"),
        }

    test_cases = [
        RuleTestCase(
            name="External assumption of admin role should alert",
            event={
                "event_id": "test-3",
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "requestParameters": {"roleArn": "arn:aws:iam::123:role/AdminAccess"},
                "userIdentity": {"arn": "arn:aws:iam::456:user/external-contractor"},
                "sourceIPAddress": "203.0.113.88",
            },
            should_match=True,
        ),
        RuleTestCase(
            name="Internal private IP assumption should not alert",
            event={
                "event_id": "test-4",
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "requestParameters": {"roleArn": "arn:aws:iam::123:role/AdminAccess"},
                "userIdentity": {"arn": "arn:aws:iam::123:user/internal-deployer"},
                "sourceIPAddress": "10.0.1.25",
            },
            should_match=False,
        ),
    ]

    return DetectionRule(
        rule_id=rule_id,
        name=name,
        description=desc,
        severity=DetectionSeverity.CRITICAL,
        lifecycle=RuleLifecycle.PRODUCTION,
        mitre=mitre,
        evaluator=evaluator,
        extract_entity=entity,
        extract_evidence=evidence,
        test_cases=test_cases,
    )
