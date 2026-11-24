from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PSRDomain(str, Enum):
    GOVERNANCE = "GOVERNANCE"
    INFOSEC = "INFOSEC"
    PERSEC = "PERSEC"
    PHYSEC = "PHYSEC"


class ControlStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ArchitectureAsset:
    asset_id: str
    asset_type: str
    environment: str
    network_isolated: bool
    tls_enforced: bool
    encryption_at_rest: bool
    customer_managed_kms: bool
    mfa_required: bool
    audit_logging_enabled: bool
    public_ingress_open: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "environment": self.environment,
            "network_isolated": self.network_isolated,
            "tls_enforced": self.tls_enforced,
            "encryption_at_rest": self.encryption_at_rest,
            "customer_managed_kms": self.customer_managed_kms,
            "mfa_required": self.mfa_required,
            "audit_logging_enabled": self.audit_logging_enabled,
            "public_ingress_open": self.public_ingress_open,
        }


@dataclass
class ControlFinding:
    control_id: str
    domain: PSRDomain
    asset_id: str
    status: ControlStatus
    risk: RiskTier
    title: str
    remediation_directive: str


@dataclass
class GovernanceAssessmentReport:
    total_assets: int
    overall_compliance_score: float
    findings_count: int
    critical_findings: int
    high_findings: int
    findings: list[ControlFinding]
    assessment_hash: str


class PSRArchitectureEvaluator:
    """Evaluates cloud architecture designs against PSR and NZISM controls."""

    def __init__(self, target_framework: str = "NZISM+PSR") -> None:
        self.target_framework = target_framework

    def evaluate_asset(self, asset: ArchitectureAsset) -> list[ControlFinding]:
        findings: list[ControlFinding] = []

        # 1. NZISM 14.2.3: Cryptographic transit protection
        if not asset.tls_enforced:
            findings.append(
                ControlFinding(
                    control_id="NZISM-14.2.3",
                    domain=PSRDomain.INFOSEC,
                    asset_id=asset.asset_id,
                    status=ControlStatus.NON_COMPLIANT,
                    risk=RiskTier.CRITICAL if asset.public_ingress_open else RiskTier.HIGH,
                    title="Missing enforced TLS cryptographic transit protection",
                    remediation_directive="Enforce TLS 1.3 encryption across all communication endpoints.",
                )
            )

        # 2. PSR INFOSEC-4 / NZISM 14.1.1: Customer-managed encryption at rest
        if not asset.encryption_at_rest or not asset.customer_managed_kms:
            findings.append(
                ControlFinding(
                    control_id="PSR-INFOSEC-4",
                    domain=PSRDomain.INFOSEC,
                    asset_id=asset.asset_id,
                    status=ControlStatus.NON_COMPLIANT,
                    risk=RiskTier.HIGH,
                    title="Storage volume lacks customer-managed KMS encryption at rest",
                    remediation_directive="Enable AES-256 or ChaCha20 encryption using dedicated KMS keys.",
                )
            )

        # 3. NZISM 16.1.1: Zero Trust privileged identity and MFA
        if not asset.mfa_required and asset.environment.lower() == "production":
            findings.append(
                ControlFinding(
                    control_id="NZISM-16.1.1",
                    domain=PSRDomain.INFOSEC,
                    asset_id=asset.asset_id,
                    status=ControlStatus.NON_COMPLIANT,
                    risk=RiskTier.CRITICAL,
                    title="Privileged administrative access without mandatory multi-factor authentication",
                    remediation_directive="Enforce hardware-bound FIDO2/WebAuthn MFA on privileged IAM roles.",
                )
            )

        # 4. NZISM 18.3.1: Immutable audit retention
        if not asset.audit_logging_enabled:
            findings.append(
                ControlFinding(
                    control_id="NZISM-18.3.1",
                    domain=PSRDomain.GOVERNANCE,
                    asset_id=asset.asset_id,
                    status=ControlStatus.NON_COMPLIANT,
                    risk=RiskTier.MEDIUM,
                    title="Audit trail and security event telemetry disabled",
                    remediation_directive="Enable write-once immutable audit logging dispatched to central SIEM.",
                )
            )

        # 5. PSR GOV-2: Public ingress isolation
        if asset.public_ingress_open and not asset.network_isolated:
            findings.append(
                ControlFinding(
                    control_id="PSR-GOV-2",
                    domain=PSRDomain.GOVERNANCE,
                    asset_id=asset.asset_id,
                    status=ControlStatus.NON_COMPLIANT,
                    risk=RiskTier.CRITICAL,
                    title="Unrestricted public network ingress on non-isolated resource",
                    remediation_directive="Place asset behind a Web Application Firewall (WAF) or private subnet.",
                )
            )

        return findings

    def assess_architecture(
        self, assets: list[ArchitectureAsset]
    ) -> GovernanceAssessmentReport:
        if not assets:
            return GovernanceAssessmentReport(
                total_assets=0,
                overall_compliance_score=100.0,
                findings_count=0,
                critical_findings=0,
                high_findings=0,
                findings=[],
                assessment_hash=hashlib.sha256(b"empty").hexdigest(),
            )

        all_findings: list[ControlFinding] = []
        for asset in assets:
            all_findings.extend(self.evaluate_asset(asset))

        critical_count = sum(1 for f in all_findings if f.risk == RiskTier.CRITICAL)
        high_count = sum(1 for f in all_findings if f.risk == RiskTier.HIGH)

        # Base score starts at 100%, each critical deducts 15%, high deducts 5%, medium deducts 2%
        deductions = (
            critical_count * 15.0
            + high_count * 5.0
            + sum(1 for f in all_findings if f.risk == RiskTier.MEDIUM) * 2.0
        )
        final_score = max(0.0, round(100.0 - (deductions / len(assets)), 2))

        # Generate cryptographic audit hash of findings
        serialized_findings = json.dumps(
            [
                {
                    "control_id": f.control_id,
                    "asset_id": f.asset_id,
                    "risk": f.risk.value,
                }
                for f in all_findings
            ],
            sort_keys=True,
        )
        assessment_hash = hashlib.sha256(serialized_findings.encode("utf-8")).hexdigest()

        return GovernanceAssessmentReport(
            total_assets=len(assets),
            overall_compliance_score=final_score,
            findings_count=len(all_findings),
            critical_findings=critical_count,
            high_findings=high_count,
            findings=all_findings,
            assessment_hash=assessment_hash,
        )
