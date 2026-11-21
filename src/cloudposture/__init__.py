"""Cloud security posture service with detection-as-code and automated triage."""

from cloudposture.detection_engine import (
    DetectionAlert,
    DetectionEngine,
    DetectionRule,
    DetectionSeverity,
    MitreAttack,
    RuleLifecycle,
    RuleTestCase,
    build_anomalous_iam_assume_role_rule,
    build_aws_console_login_without_mfa_rule,
)
from cloudposture.triage_automation import (
    AlertTriagePipeline,
    EnrichedAlert,
    TriageContext,
)

__all__ = [
    "DetectionAlert",
    "DetectionEngine",
    "DetectionRule",
    "DetectionSeverity",
    "MitreAttack",
    "RuleLifecycle",
    "RuleTestCase",
    "build_anomalous_iam_assume_role_rule",
    "build_aws_console_login_without_mfa_rule",
    "AlertTriagePipeline",
    "EnrichedAlert",
    "TriageContext",
]
