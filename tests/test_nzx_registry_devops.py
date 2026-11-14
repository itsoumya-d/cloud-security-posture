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

def test_clean_registry_workload_creates_no_findings(session):
    service = CloudPostureService(session)
    acc = service.create_account("aws", "123456789012", "nzx-smart-registry-prod")

    # Clean compliant registry workload
    service.sync_resources(acc.id, [{
        "resource_id": "arn:aws:eks:ap-southeast-2:123456789012:cluster/nzx-registry-prod",
        "resource_type": "registry_cluster",
        "region": "ap-southeast-2",
        "config": {
            "network_isolation_enabled": True,
            "legacy_bridge_egress_controlled": True,
            "oidc_federation_enabled": True,
            "dr_replication_enabled": True,
            "rpo_minutes": 5,
            "audit_stream_enabled": True,
            "worm_immutability_locked": True,
            "retention_days": 2555
        },
        "tags": {
            "domain": "registry",
            "tier": "registry_core",
            "classification": "tier1_exchange",
            "owner": "devops-platform",
            "environment": "production"
        }
    }])

    assert service.findings() == []

def test_registry_network_isolation_violation(session):
    service = CloudPostureService(session)
    acc = service.create_account("aws", "123456789012", "nzx-smart-registry-prod")

    # Incompliant registry: isolation disabled and uncontrolled legacy egress
    service.sync_resources(acc.id, [{
        "resource_id": "arn:aws:eks:ap-southeast-2:123456789012:cluster/nzx-registry-prod",
        "resource_type": "registry_cluster",
        "region": "ap-southeast-2",
        "config": {
            "network_isolation_enabled": False,
            "legacy_bridge_egress_controlled": False,
            "oidc_federation_enabled": True,
            "dr_replication_enabled": True,
            "rpo_minutes": 5,
            "audit_stream_enabled": True,
            "worm_immutability_locked": True,
            "retention_days": 2555
        },
        "tags": {
            "domain": "registry",
            "tier": "registry_core",
            "classification": "tier1_exchange",
            "owner": "devops-platform",
            "environment": "production"
        }
    }])

    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "NZX_REGISTRY_NETWORK_ISOLATION" in rule_ids
    iso_finding = next(f for f in findings if f.rule_id == "NZX_REGISTRY_NETWORK_ISOLATION")
    assert iso_finding.severity == "critical"

    # Resolve finding
    resolved = service.resolve_finding(iso_finding.id, "Network policies applied to isolate namespace")
    assert resolved.status == "resolved"
    assert len(service.findings("open")) == 0

def test_cicd_provenance_and_image_signing(session):
    service = CloudPostureService(session)
    acc = service.create_account("azure", "nzx-sub-devops-01", "nzx-cicd-services")

    # Clean compliant pipeline
    service.sync_resources(acc.id, [{
        "resource_id": "azure-devops/pipelines/clean-pipeline",
        "resource_type": "cicd_pipeline",
        "region": "australiasoutheast",
        "config": {
            "image_signing_enforced": True,
            "slsa_provenance_level": 3,
            "vulnerability_gate_blocking": True,
            "oidc_federation_enabled": True,
            "long_lived_credentials_detected": False
        },
        "tags": {
            "domain": "nzx",
            "component": "ci_cd",
            "owner": "platform-eng",
            "environment": "production"
        }
    }])
    assert service.findings() == []

    # Insecure pipeline missing Cosign image signing and SLSA 3
    service.sync_resources(acc.id, [{
        "resource_id": "azure-devops/pipelines/insecure-pipeline",
        "resource_type": "cicd_pipeline",
        "region": "australiasoutheast",
        "config": {
            "image_signing_enforced": False,
            "slsa_provenance_level": 1,
            "vulnerability_gate_blocking": False,
            "oidc_federation_enabled": False,
            "long_lived_credentials_detected": True
        },
        "tags": {
            "domain": "nzx",
            "component": "ci_cd",
            "owner": "platform-eng",
            "environment": "production"
        }
    }])

    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "NZX_CICD_PROVENANCE_SIGNATURE" in rule_ids
    assert "NZX_OIDC_WORKLOAD_IDENTITY" in rule_ids

def test_fma_7_year_worm_retention_and_dr_rpo(session):
    service = CloudPostureService(session)
    acc = service.create_account("aws", "987654321098", "nzx-market-data-prod")

    # Incompliant financial data store: 365 days retention (needs 2555 for FMA), no WORM, and 120m RPO
    service.sync_resources(acc.id, [{
        "resource_id": "arn:aws:s3:::nzx-smart-settlement-audit-stream",
        "resource_type": "financial_data_store",
        "region": "ap-southeast-2",
        "config": {
            "audit_stream_enabled": True,
            "worm_immutability_locked": False,
            "retention_days": 365,
            "dr_replication_enabled": False,
            "rpo_minutes": 120
        },
        "tags": {
            "domain": "financial_markets",
            "data_type": "transaction_ledger",
            "criticality": "mission_critical",
            "owner": "devops-data",
            "environment": "production"
        }
    }])

    findings = service.findings()
    rule_ids = {f.rule_id for f in findings}
    assert "FMA_WORM_TRANSACTION_RETENTION" in rule_ids
    assert "NZX_DISASTER_RECOVERY_RPO" in rule_ids
    worm_finding = next(f for f in findings if f.rule_id == "FMA_WORM_TRANSACTION_RETENTION")
    assert worm_finding.severity == "critical"
