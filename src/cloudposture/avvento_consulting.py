"""Avvento Consulting: Multi-Cloud Infrastructure & Governance Assessment Engine.

Provides automated cloud architecture evaluation, NZISM compliance checks,
configuration drift detection, and prioritized remediation planning for
enterprise cloud consulting engagements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class Finding:
    rule_id: str
    severity: str  # critical, high, medium, low
    resource_id: str
    resource_type: str
    description: str
    remediation_guidance: str
    nzism_control: str
    estimated_hours: float


@dataclass
class AssessmentResult:
    assessment_id: str
    company_name: str
    timestamp: str
    resilience_score: float  # 0.0 to 100.0
    nzism_compliance_percentage: float
    total_resources: int
    findings: list[Finding] = field(default_factory=list)
    remediation_nzd_estimate: float = 0.0
    summary: dict[str, int] = field(default_factory=dict)


class AvventoCloudConsultingEngine:
    """Enterprise cloud consultancy assessment and governance engine."""

    NZD_HOURLY_RATE = 180.0  # Senior Cloud Consultant NZD/hour benchmark

    def __init__(self, assessment_id: str, company_name: str = "Client Engagement") -> None:
        self.assessment_id = assessment_id
        self.company_name = company_name

    def assess_infrastructure(self, resources: list[dict[str, Any]]) -> AssessmentResult:
        """Evaluates infrastructure resources against NZISM and cloud architecture baselines."""
        findings: list[Finding] = []
        total_resources = len(resources)
        passed_rules = 0
        total_checks = 0

        for res in resources:
            res_id = res.get("id", "unknown-resource")
            res_type = res.get("type", "generic")
            res.get("provider", "aws")
            config = res.get("config", {})

            # Rule 1: Encryption at Rest (NZISM 16.1.1)
            total_checks += 1
            if not config.get("encrypted_at_rest", False):
                findings.append(Finding(
                    rule_id="AVV-SEC-001",
                    severity="high",
                    resource_id=res_id,
                    resource_type=res_type,
                    description=f"{res_type} '{res_id}' does not enforce encryption at rest.",
                    remediation_guidance="Enable KMS/CMK customer-managed key encryption with automated key rotation.",
                    nzism_control="NZISM 16.1.1",
                    estimated_hours=2.5
                ))
            else:
                passed_rules += 1

            # Rule 2: Public Network Ingress (NZISM 14.2.3)
            total_checks += 1
            public_ingress = config.get("public_ingress", False)
            open_ports = config.get("open_ports", [])
            sensitive_ports = {22, 3389, 5432, 3306, 27017, 6379}
            exposed_sensitive = set(open_ports).intersection(sensitive_ports)

            if public_ingress and exposed_sensitive:
                findings.append(Finding(
                    rule_id="AVV-NET-002",
                    severity="critical",
                    resource_id=res_id,
                    resource_type=res_type,
                    description=f"{res_type} '{res_id}' exposes sensitive ports {sorted(exposed_sensitive)} to 0.0.0.0/0.",
                    remediation_guidance="Restrict ingress via Security Groups/Firewall rules to VPN/PrivateLink VPC endpoints.",
                    nzism_control="NZISM 14.2.3",
                    estimated_hours=3.5
                ))
            else:
                passed_rules += 1

            # Rule 3: Automated Backup & Point-in-Time Recovery (NZISM 18.3.1)
            if res_type in ("database", "storage_bucket", "persistent_volume"):
                total_checks += 1
                backup_retention_days = config.get("backup_retention_days", 0)
                if backup_retention_days < 7:
                    findings.append(Finding(
                        rule_id="AVV-RES-003",
                        severity="medium",
                        resource_id=res_id,
                        resource_type=res_type,
                        description=f"{res_type} '{res_id}' has backup retention of {backup_retention_days} days (<7 days minimum).",
                        remediation_guidance="Configure automated daily backup snapshots with cross-region replication and 30-day lifecycle retention.",
                        nzism_control="NZISM 18.3.1",
                        estimated_hours=1.5
                    ))
                else:
                    passed_rules += 1

            # Rule 4: Multi-AZ / Multi-Region Redundancy (Resilience Baseline)
            if res_type in ("database", "cluster", "application_gateway"):
                total_checks += 1
                multi_az = config.get("multi_az", False)
                if not multi_az:
                    findings.append(Finding(
                        rule_id="AVV-ARC-004",
                        severity="medium",
                        resource_id=res_id,
                        resource_type=res_type,
                        description=f"{res_type} '{res_id}' lacks Multi-AZ high-availability deployment.",
                        remediation_guidance="Provision secondary standby replica across alternate availability zones with automated failover.",
                        nzism_control="Cloud Architecture Pillar 3",
                        estimated_hours=4.0
                    ))
                else:
                    passed_rules += 1

        # Calculate scores
        compliance_pct = round((passed_rules / total_checks * 100.0) if total_checks > 0 else 100.0, 1)

        # Penalty score based on severity
        penalties = {"critical": 25.0, "high": 12.0, "medium": 5.0, "low": 2.0}
        total_penalty = sum(penalties.get(f.severity, 0.0) for f in findings)
        resilience_score = max(0.0, round(100.0 - total_penalty, 1))

        # Remediation cost calculation
        total_hours = sum(f.estimated_hours for f in findings)
        remediation_nzd = round(total_hours * self.NZD_HOURLY_RATE, 2)

        summary = {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low")
        }

        return AssessmentResult(
            assessment_id=self.assessment_id,
            company_name=self.company_name,
            timestamp=datetime.now(UTC).isoformat(),
            resilience_score=resilience_score,
            nzism_compliance_percentage=compliance_pct,
            total_resources=total_resources,
            findings=findings,
            remediation_nzd_estimate=remediation_nzd,
            summary=summary
        )

    def export_consulting_manifest(self, result: AssessmentResult) -> dict[str, Any]:
        """Generates structured JSON manifest for client delivery."""
        return {
            "assessment_id": result.assessment_id,
            "company_name": result.company_name,
            "evaluated_at": result.timestamp,
            "metrics": {
                "resilience_score": result.resilience_score,
                "nzism_compliance_percentage": result.nzism_compliance_percentage,
                "total_resources": result.total_resources,
                "total_findings": len(result.findings),
                "remediation_nzd_estimate": result.remediation_nzd_estimate
            },
            "findings_by_severity": result.summary,
            "remediation_roadmap": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "resource": f"{f.resource_type}:{f.resource_id}",
                    "nzism_control": f.nzism_control,
                    "action": f.remediation_guidance,
                    "estimated_hours": f.estimated_hours,
                    "estimated_nzd": round(f.estimated_hours * self.NZD_HOURLY_RATE, 2)
                }
                for f in sorted(result.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4))
            ]
        }
