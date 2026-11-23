"""Tests for Avvento Consulting Multi-Cloud Assessment & Governance Engine."""
from __future__ import annotations

from cloudposture.avvento_consulting import AvventoCloudConsultingEngine


def test_clean_infrastructure_achieves_perfect_score():
    engine = AvventoCloudConsultingEngine(assessment_id="AVV-TEST-001", company_name="Avvento Enterprise Client")
    resources = [
        {
            "id": "db-prod-primary",
            "type": "database",
            "provider": "aws",
            "config": {
                "encrypted_at_rest": True,
                "public_ingress": False,
                "open_ports": [],
                "backup_retention_days": 30,
                "multi_az": True
            }
        },
        {
            "id": "s3-client-archive",
            "type": "storage_bucket",
            "provider": "aws",
            "config": {
                "encrypted_at_rest": True,
                "public_ingress": False,
                "open_ports": [],
                "backup_retention_days": 14
            }
        }
    ]

    result = engine.assess_infrastructure(resources)

    assert result.resilience_score == 100.0
    assert result.nzism_compliance_percentage == 100.0
    assert len(result.findings) == 0
    assert result.remediation_nzd_estimate == 0.0
    assert result.summary == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_detects_unencrypted_resources():
    engine = AvventoCloudConsultingEngine(assessment_id="AVV-TEST-002")
    resources = [
        {
            "id": "vol-legacy-app",
            "type": "persistent_volume",
            "config": {
                "encrypted_at_rest": False,
                "public_ingress": False,
                "backup_retention_days": 14
            }
        }
    ]

    result = engine.assess_infrastructure(resources)

    assert any(f.rule_id == "AVV-SEC-001" and f.severity == "high" for f in result.findings)
    assert result.resilience_score < 100.0
    assert result.remediation_nzd_estimate > 0.0


def test_detects_public_sensitive_ports():
    engine = AvventoCloudConsultingEngine(assessment_id="AVV-TEST-003")
    resources = [
        {
            "id": "vm-bastion-exposed",
            "type": "virtual_machine",
            "config": {
                "encrypted_at_rest": True,
                "public_ingress": True,
                "open_ports": [22, 443]  # port 22 exposed to 0.0.0.0/0
            }
        }
    ]

    result = engine.assess_infrastructure(resources)

    critical_findings = [f for f in result.findings if f.severity == "critical"]
    assert len(critical_findings) == 1
    assert critical_findings[0].rule_id == "AVV-NET-002"
    assert "22" in critical_findings[0].description


def test_detects_backup_retention_shortfall():
    engine = AvventoCloudConsultingEngine(assessment_id="AVV-TEST-004")
    resources = [
        {
            "id": "db-analytics",
            "type": "database",
            "config": {
                "encrypted_at_rest": True,
                "public_ingress": False,
                "backup_retention_days": 3,  # <7 days minimum
                "multi_az": True
            }
        }
    ]

    result = engine.assess_infrastructure(resources)

    assert any(f.rule_id == "AVV-RES-003" and f.severity == "medium" for f in result.findings)


def test_detects_multi_az_absence_on_production_database():
    engine = AvventoCloudConsultingEngine(assessment_id="AVV-TEST-005")
    resources = [
        {
            "id": "db-single-instance",
            "type": "database",
            "config": {
                "encrypted_at_rest": True,
                "public_ingress": False,
                "backup_retention_days": 14,
                "multi_az": False
            }
        }
    ]

    result = engine.assess_infrastructure(resources)

    assert any(f.rule_id == "AVV-ARC-004" for f in result.findings)


def test_export_consulting_manifest_structure():
    engine = AvventoCloudConsultingEngine(assessment_id="AVV-2026-ENGAGEMENT", company_name="Auckland Enterprise Ltd")
    resources = [
        {
            "id": "db-core",
            "type": "database",
            "config": {
                "encrypted_at_rest": False,
                "public_ingress": True,
                "open_ports": [5432],
                "backup_retention_days": 1,
                "multi_az": False
            }
        }
    ]

    result = engine.assess_infrastructure(resources)
    manifest = engine.export_consulting_manifest(result)

    assert manifest["assessment_id"] == "AVV-2026-ENGAGEMENT"
    assert manifest["company_name"] == "Auckland Enterprise Ltd"
    assert "metrics" in manifest
    assert manifest["metrics"]["total_findings"] == 4
    assert len(manifest["remediation_roadmap"]) == 4
    # Roadmap should be sorted by severity: critical first
    assert manifest["remediation_roadmap"][0]["severity"] == "critical"
