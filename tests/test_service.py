import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cloudposture.db import Base
from cloudposture.service import CloudPostureService, NotFoundError, ValidationError


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s = factory()
    yield s
    s.close()


def resource(**overrides):
    data = {
        "resource_id": "bucket-1",
        "resource_type": "s3_bucket",
        "region": "ap-southeast-2",
        "config": {"public": False, "encrypted": True},
        "tags": {"owner": "platform", "environment": "prod"},
    }
    data.update(overrides)
    return data


def test_account_creation_and_duplicate(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123456789012", "prod")
    assert account.provider == "aws"
    with pytest.raises(ValidationError, match="already exists"):
        service.create_account("aws", "123456789012", "prod")


def test_unknown_provider_rejected(session):
    with pytest.raises(ValidationError, match="unsupported provider"):
        CloudPostureService(session).create_account("oracle", "1", "x")


def test_sync_clean_resource_creates_no_findings(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    result = service.sync_resources(account.id, [resource()])
    assert result["created"] == 1
    assert service.findings() == []


def test_public_unencrypted_bucket_findings(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [resource(config={"public": True, "encrypted": False})])
    rules = {f.rule_id for f in service.findings()}
    assert {"S3_PUBLIC", "S3_UNENCRYPTED"} <= rules


def test_open_admin_security_group_finding(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [resource(
        resource_id="sg-1", resource_type="security_group",
        config={"ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]},
    )])
    rules = {f.rule_id for f in service.findings()}
    assert "SG_OPEN_ADMIN" in rules


def test_unencrypted_volume_and_mfa_findings(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [
        resource(resource_id="vol-1", resource_type="volume", config={"encrypted": False}),
        resource(resource_id="user-1", resource_type="iam_user", config={"mfa_enabled": False}),
    ])
    rules = {f.rule_id for f in service.findings()}
    assert {"VOLUME_UNENCRYPTED", "IAM_MFA"} <= rules


def test_missing_tags_finding(session):
    service = CloudPostureService(session)
    account = service.create_account("azure", "sub-1", "prod")
    service.sync_resources(account.id, [resource(resource_id="disk-1", resource_type="disk", tags={})])
    assert any(f.rule_id == "TAGS_REQUIRED" for f in service.findings())


def test_resolve_finding_and_reject_double(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [resource(config={"public": True, "encrypted": True})])
    finding = service.findings()[0]
    resolved = service.resolve_finding(finding.id, "Blocked public access")
    assert resolved.status == "resolved"
    with pytest.raises(ValidationError, match="already resolved"):
        service.resolve_finding(finding.id, "Again")


def test_reopened_finding_after_resync(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [resource(config={"public": True, "encrypted": True})])
    finding = service.findings()[0]
    service.resolve_finding(finding.id, "Fixed")
    service.sync_resources(account.id, [resource(config={"public": True, "encrypted": True})])
    assert service.findings("open")[0].rule_id == "S3_PUBLIC"


def test_summary_counts(session):
    service = CloudPostureService(session)
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [resource(config={"public": True, "encrypted": False})])
    summary = service.summary()
    assert summary["accounts"] == 1
    assert summary["resources"] == 1
    assert summary["open_findings"] == 2
    assert summary["open_by_severity"]["critical"] == 1


def test_audit_trail(session):
    service = CloudPostureService(session, actor="analyst")
    account = service.create_account("aws", "123", "prod")
    service.sync_resources(account.id, [resource()])
    actions = [entry["action"] for entry in service.audit()]
    assert actions == ["account_created", "resources_synced"]
