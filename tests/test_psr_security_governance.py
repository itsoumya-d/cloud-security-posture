from __future__ import annotations

from cloudposture.psr_security_governance import (
    ArchitectureAsset,
    ControlStatus,
    PSRArchitectureEvaluator,
    PSRDomain,
    RiskTier,
)


def _make_hardened_asset(asset_id: str = "srv-prod-01") -> ArchitectureAsset:
    return ArchitectureAsset(
        asset_id=asset_id,
        asset_type="compute.service",
        environment="production",
        network_isolated=True,
        tls_enforced=True,
        encryption_at_rest=True,
        customer_managed_kms=True,
        mfa_required=True,
        audit_logging_enabled=True,
        public_ingress_open=False,
    )


def test_fully_compliant_asset_zero_findings():
    evaluator = PSRArchitectureEvaluator()
    asset = _make_hardened_asset()
    findings = evaluator.evaluate_asset(asset)
    assert len(findings) == 0

    report = evaluator.assess_architecture([asset])
    assert report.total_assets == 1
    assert report.overall_compliance_score == 100.0
    assert report.critical_findings == 0
    assert len(report.findings) == 0


def test_missing_tls_transit_protection():
    evaluator = PSRArchitectureEvaluator()
    asset = _make_hardened_asset()
    asset.tls_enforced = False
    asset.public_ingress_open = True

    findings = evaluator.evaluate_asset(asset)
    tls_findings = [f for f in findings if f.control_id == "NZISM-14.2.3"]
    assert len(tls_findings) == 1
    assert tls_findings[0].risk == RiskTier.CRITICAL
    assert tls_findings[0].status == ControlStatus.NON_COMPLIANT
    assert tls_findings[0].domain == PSRDomain.INFOSEC


def test_unencrypted_storage_kms():
    evaluator = PSRArchitectureEvaluator()
    asset = _make_hardened_asset()
    asset.customer_managed_kms = False

    findings = evaluator.evaluate_asset(asset)
    kms_findings = [f for f in findings if f.control_id == "PSR-INFOSEC-4"]
    assert len(kms_findings) == 1
    assert kms_findings[0].risk == RiskTier.HIGH


def test_production_privileged_mfa_requirement():
    evaluator = PSRArchitectureEvaluator()
    asset = _make_hardened_asset()
    asset.mfa_required = False

    findings = evaluator.evaluate_asset(asset)
    mfa_findings = [f for f in findings if f.control_id == "NZISM-16.1.1"]
    assert len(mfa_findings) == 1
    assert mfa_findings[0].risk == RiskTier.CRITICAL


def test_audit_logging_disabled():
    evaluator = PSRArchitectureEvaluator()
    asset = _make_hardened_asset()
    asset.audit_logging_enabled = False

    findings = evaluator.evaluate_asset(asset)
    audit_findings = [f for f in findings if f.control_id == "NZISM-18.3.1"]
    assert len(audit_findings) == 1
    assert audit_findings[0].risk == RiskTier.MEDIUM


def test_unrestricted_public_ingress():
    evaluator = PSRArchitectureEvaluator()
    asset = _make_hardened_asset()
    asset.public_ingress_open = True
    asset.network_isolated = False

    findings = evaluator.evaluate_asset(asset)
    ingress_findings = [f for f in findings if f.control_id == "PSR-GOV-2"]
    assert len(ingress_findings) == 1
    assert ingress_findings[0].risk == RiskTier.CRITICAL


def test_architecture_assessment_aggregation():
    evaluator = PSRArchitectureEvaluator()
    asset1 = _make_hardened_asset("srv-01")
    asset2 = _make_hardened_asset("srv-02")
    asset2.tls_enforced = False
    asset2.mfa_required = False

    report = evaluator.assess_architecture([asset1, asset2])
    assert report.total_assets == 2
    assert report.findings_count > 0
    assert report.critical_findings > 0
    assert report.overall_compliance_score < 100.0
    assert len(report.assessment_hash) == 64


def test_empty_architecture_handling():
    evaluator = PSRArchitectureEvaluator()
    report = evaluator.assess_architecture([])
    assert report.total_assets == 0
    assert report.overall_compliance_score == 100.0
    assert report.findings_count == 0
