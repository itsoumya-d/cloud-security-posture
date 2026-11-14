from __future__ import annotations

from typing import Any

RuleTuple = tuple[str, str, str, str, str]

def evaluate_nzx_registry_posture(
    resource_type: str,
    config: dict[str, Any],
    tags: dict[str, Any]
) -> list[RuleTuple]:
    """
    Evaluates cloud workloads, CI/CD pipelines, and data services against
    NZX modern registry security posture standards and Financial Markets Authority (FMA)
    regulatory governance mandates.
    """
    checks: list[RuleTuple] = []

    domain = tags.get("domain", "").lower()
    is_financial_or_registry = (
        domain in {"registry", "financial_markets", "nzx", "fintech", "smart_shares"}
        or tags.get("classification") in {"tier1_exchange", "registry_platform", "market_critical"}
        or resource_type in {"registry_cluster", "cicd_pipeline", "market_data_service", "financial_data_store"}
    )

    if not is_financial_or_registry:
        return checks

    # 1. NZX Registry Workload Zero-Trust Network & Legacy Isolation Check
    if resource_type in {"registry_cluster", "market_data_service"} or tags.get("tier") == "registry_core":
        isolation_enabled = bool(config.get("network_isolation_enabled", False))
        legacy_egress_controlled = bool(config.get("legacy_bridge_egress_controlled", False))
        if not isolation_enabled or not legacy_egress_controlled:
            checks.append((
                "NZX_REGISTRY_NETWORK_ISOLATION",
                "Modern registry workload lacks zero-trust network isolation from legacy systems",
                "critical",
                f"network_isolation={isolation_enabled} legacy_egress_controlled={legacy_egress_controlled}",
                "Enforce strict Kubernetes/VPC network policies isolating modern registry pods from legacy environments."
            ))

    # 2. CI/CD Immutable Artifact Provenance & Cryptographic Signature Check
    if resource_type in {"cicd_pipeline", "container_registry"} or tags.get("component") in {"ci_cd", "deployment_gate"}:
        cosign_enforced = bool(config.get("image_signing_enforced", False))
        slsa_level = int(config.get("slsa_provenance_level", 0))
        vuln_gate_blocking = bool(config.get("vulnerability_gate_blocking", False))

        if not cosign_enforced or slsa_level < 3 or not vuln_gate_blocking:
            checks.append((
                "NZX_CICD_PROVENANCE_SIGNATURE",
                "CI/CD deployment pipeline allows unsigned container artifacts or missing SLSA provenance",
                "high",
                f"image_signing_enforced={cosign_enforced} slsa_level={slsa_level} vuln_gate_blocking={vuln_gate_blocking}",
                "Require Cosign keyless container signatures, SLSA Level 3 build provenance, and automated blocking CVE gates."
            ))

    # 3. Ephemeral OIDC Workload Identity Federation vs Long-Lived IAM Keys Check
    if resource_type in {"registry_cluster", "cicd_pipeline", "service_principal"} or config.get("auth_type") == "iam":
        oidc_enabled = bool(config.get("oidc_federation_enabled", False))
        has_long_lived_keys = bool(config.get("long_lived_credentials_detected", False))

        if not oidc_enabled or has_long_lived_keys:
            checks.append((
                "NZX_OIDC_WORKLOAD_IDENTITY",
                "Workload relies on static long-lived cloud credentials instead of ephemeral OIDC federation",
                "high",
                f"oidc_federation_enabled={oidc_enabled} long_lived_keys={has_long_lived_keys}",
                "Migrate pipeline service connections to short-lived OpenID Connect (OIDC) workload identity federation."
            ))

    # 4. FMA & NZX 7-Year Immutable WORM Transaction Audit Retention Check
    if resource_type in {"financial_data_store", "registry_cluster"} or tags.get("data_type") in {"transaction_ledger", "registry_records"}:
        audit_stream_enabled = bool(config.get("audit_stream_enabled", False))
        worm_lock = bool(config.get("worm_immutability_locked", False))
        retention_days = int(config.get("retention_days", 0))

        if not audit_stream_enabled or not worm_lock or retention_days < 2555:
            checks.append((
                "FMA_WORM_TRANSACTION_RETENTION",
                "Financial registry audit stream does not meet FMA 7-year (2555 days) immutable retention mandate",
                "critical",
                f"audit_stream={audit_stream_enabled} worm_locked={worm_lock} retention_days={retention_days}",
                "Enable object lock with compliance mode WORM retention for minimum 2555 days per FMC Act 2013."
            ))

    # 5. Multi-Region Disaster Recovery RPO / Failover Telemetry Check
    if resource_type in {"registry_cluster", "financial_data_store"} or tags.get("criticality") == "mission_critical":
        dr_replication = bool(config.get("dr_replication_enabled", False))
        rpo_minutes = int(config.get("rpo_minutes", 999))

        if not dr_replication or rpo_minutes > 15:
            checks.append((
                "NZX_DISASTER_RECOVERY_RPO",
                "Market registry platform lacks multi-region disaster recovery replication meeting NZX 15-minute RPO threshold",
                "high",
                f"dr_replication_enabled={dr_replication} rpo_minutes={rpo_minutes}",
                "Configure automated cross-region read replica streaming and failover verification to maintain RPO <= 15 minutes."
            ))

    return checks
