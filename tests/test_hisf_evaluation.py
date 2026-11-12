import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cloudposture.db import Base
from cloudposture.service import CloudPostureService


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s = factory()
    yield s
    s.close()


def test_hisf_api_gateway_unauthenticated_access_flagged(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "111222333444", "health-prod")
    service.sync_resources(
        account.id,
        [
            {
                "resource_id": "api-gateway-patients",
                "resource_type": "api_gateway",
                "region": "ap-southeast-2",
                "config": {"auth_enabled": False, "allow_unauthenticated": True, "min_tls_version": "1.2"},
                "tags": {"owner": "digital-health", "environment": "prod"},
            }
        ],
    )
    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "HISF_API_AUTH_REQUIRED" in rule_ids
    api_finding = next(f for f in findings if f.rule_id == "HISF_API_AUTH_REQUIRED")
    assert api_finding.severity == "critical"
    assert "HISO 10029" in api_finding.remediation


def test_nzism_insecure_tls_version_flagged(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "111222333445", "health-legacy")
    service.sync_resources(
        account.id,
        [
            {
                "resource_id": "legacy-patient-portal",
                "resource_type": "api_gateway",
                "region": "ap-southeast-2",
                "config": {"auth_enabled": True, "min_tls_version": "1.0", "allow_insecure_http": False},
                "tags": {"owner": "integration-team", "environment": "prod"},
            }
        ],
    )
    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "NZISM_TLS_MODERN" in rule_ids
    assert "HISF_API_AUTH_REQUIRED" not in rule_ids
    tls_finding = next(f for f in findings if f.rule_id == "NZISM_TLS_MODERN")
    assert tls_finding.severity == "high"
    assert "NZISM Section 17.1" in tls_finding.remediation


def test_hisf_phi_data_store_without_kms_encryption_flagged(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "111222333446", "clinical-data")
    service.sync_resources(
        account.id,
        [
            {
                "resource_id": "ehr-aurora-cluster",
                "resource_type": "ehr_database",
                "region": "ap-southeast-2",
                "config": {
                    "encrypted": False,
                    "kms_key_id": None,
                    "audit_logging_enabled": True,
                    "audit_retention_days": 400,
                    "automated_backups": True,
                    "backup_immutability": True,
                },
                "tags": {
                    "owner": "clinical-data-platform",
                    "environment": "prod",
                    "data_classification": "phi",
                },
            }
        ],
    )
    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "HISF_PHI_ENCRYPTION_REST" in rule_ids
    phi_finding = next(f for f in findings if f.rule_id == "HISF_PHI_ENCRYPTION_REST")
    assert phi_finding.severity == "critical"


def test_hisf_insufficient_audit_logging_retention_flagged(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "111222333447", "health-analytics")
    service.sync_resources(
        account.id,
        [
            {
                "resource_id": "health-lakehouse-bucket",
                "resource_type": "s3_bucket",
                "region": "ap-southeast-2",
                "config": {
                    "public": False,
                    "encrypted": True,
                    "kms_key_id": "arn:aws:kms:ap-southeast-2:111222333447:key/health-cmk-01",
                    "audit_logging_enabled": True,
                    "audit_retention_days": 90,  # Below HISO 10029 required 365 days
                    "automated_backups": True,
                    "backup_immutability": True,
                },
                "tags": {
                    "owner": "analytics",
                    "environment": "prod",
                    "data_classification": "health_info",
                },
            }
        ],
    )
    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "HISF_AUDIT_LOGGING_RETENTION" in rule_ids
    audit_finding = next(f for f in findings if f.rule_id == "HISF_AUDIT_LOGGING_RETENTION")
    assert audit_finding.severity == "high"


def test_nzism_backup_immutability_missing_flagged(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "111222333448", "radiology-system")
    service.sync_resources(
        account.id,
        [
            {
                "resource_id": "pacs-image-store",
                "resource_type": "health_data_store",
                "region": "ap-southeast-2",
                "config": {
                    "encrypted": True,
                    "kms_key_id": "arn:aws:kms:ap-southeast-2:111222333448:key/pacs-key-01",
                    "audit_logging_enabled": True,
                    "audit_retention_days": 730,
                    "automated_backups": True,
                    "backup_immutability": False,  # Missing WORM immutability
                },
                "tags": {
                    "owner": "radiology",
                    "environment": "prod",
                    "domain": "healthcare",
                },
            }
        ],
    )
    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "NZISM_BACKUP_PROTECTION" in rule_ids


def test_compliant_health_system_produces_no_hisf_findings(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "111222333449", "te-whatu-ora-compliant")
    service.sync_resources(
        account.id,
        [
            {
                "resource_id": "patient-api-gateway",
                "resource_type": "api_gateway",
                "region": "ap-southeast-2",
                "config": {
                    "auth_enabled": True,
                    "allow_unauthenticated": False,
                    "min_tls_version": "1.3",
                    "allow_insecure_http": False,
                },
                "tags": {"owner": "digital-health", "environment": "prod"},
            },
            {
                "resource_id": "secure-phi-vault",
                "resource_type": "health_data_store",
                "region": "ap-southeast-2",
                "config": {
                    "encrypted": True,
                    "kms_key_id": "arn:aws:kms:ap-southeast-2:111222333449:key/phi-cmk-01",
                    "audit_logging_enabled": True,
                    "audit_retention_days": 730,
                    "automated_backups": True,
                    "backup_immutability": True,
                },
                "tags": {
                    "owner": "digital-health",
                    "environment": "prod",
                    "data_classification": "phi",
                },
            },
        ],
    )
    findings = service.findings()
    assert len(findings) == 0
