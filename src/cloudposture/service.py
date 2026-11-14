from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .tables import AccountRow, AuditRow, FindingRow, ResourceRow
from .registry_posture import evaluate_nzx_registry_posture

PROVIDERS = {"aws", "azure", "gcp"}
SEVERITIES = {"critical", "high", "medium", "low"}


class NotFoundError(Exception):
    pass


class ValidationError(Exception):
    pass


def _config(raw: dict[str, Any]) -> dict[str, Any]:
    value = raw.get("config", {})
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValidationError("config must be valid JSON") from exc


def _tags(raw: dict[str, Any]) -> dict[str, Any]:
    value = raw.get("tags", {})
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValidationError("tags must be valid JSON") from exc


class CloudPostureService:
    def __init__(self, session: Session, actor: str = "system") -> None:
        self.session = session
        self.actor = actor

    def _audit(self, action: str, reference: str, detail: str = "") -> None:
        self.session.add(AuditRow(action=action, actor=self.actor, reference=reference, detail=detail))

    def create_account(self, provider: str, account_id: str, name: str) -> AccountRow:
        provider = provider.lower()
        if provider not in PROVIDERS:
            raise ValidationError(f"unsupported provider: {provider}")
        if not account_id.strip() or not name.strip():
            raise ValidationError("account_id and name are required")
        if self.session.scalar(select(AccountRow).where(AccountRow.provider == provider, AccountRow.account_id == account_id)):
            raise ValidationError("account already exists")
        row = AccountRow(provider=provider, account_id=account_id, name=name)
        self.session.add(row)
        self.session.flush()
        self._audit("account_created", f"{provider}:{account_id}")
        self.session.commit()
        return row

    def sync_resources(self, account_id: int, resources: list[dict[str, Any]]) -> dict[str, int]:
        account = self.session.get(AccountRow, account_id)
        if account is None:
            raise NotFoundError("account not found")
        created = updated = 0
        for raw in resources:
            resource_id = str(raw.get("resource_id") or "").strip()
            resource_type = str(raw.get("resource_type") or "").strip()
            if not resource_id or not resource_type:
                raise ValidationError("resource_id and resource_type are required")
            existing = self.session.scalar(
                select(ResourceRow).where(ResourceRow.account_id == account_id, ResourceRow.resource_id == resource_id)
            )
            if existing is None:
                existing = ResourceRow(account_id=account_id, resource_id=resource_id, resource_type=resource_type)
                self.session.add(existing)
                created += 1
            else:
                updated += 1
            existing.region = str(raw.get("region") or "")
            existing.config = json.dumps(_config(raw), sort_keys=True)
            existing.tags = json.dumps(_tags(raw), sort_keys=True)
            existing.captured_at = datetime.now(timezone.utc)
            self.session.flush()
            self._evaluate(existing)
        self._audit("resources_synced", str(account_id), f"created={created} updated={updated}")
        self.session.commit()
        return {"created": created, "updated": updated}

    def _evaluate(self, resource: ResourceRow) -> None:
        config = json.loads(resource.config)
        tags = json.loads(resource.tags)
        checks: list[tuple[str, str, str, str, str]] = []
        if resource.resource_type == "s3_bucket":
            if config.get("public", False):
                checks.append(("S3_PUBLIC", "S3 bucket allows public access", "critical", "public=true", "Block public access and review bucket policy."))
            if not config.get("encrypted", False):
                checks.append(("S3_UNENCRYPTED", "S3 bucket is not encrypted", "high", "encrypted=false", "Enable default SSE-KMS encryption."))
        if resource.resource_type == "security_group":
            ingress = config.get("ingress", [])
            for rule in ingress:
                port = int(rule.get("port", 0))
                cidr = str(rule.get("cidr", ""))
                if cidr in {"0.0.0.0/0", "::/0"} and port in {22, 3389}:
                    checks.append(("SG_OPEN_ADMIN", "Security group exposes admin port to the internet", "critical", f"port={port} cidr={cidr}", "Restrict the source range or remove the rule."))
                    break
        if resource.resource_type == "volume" and not config.get("encrypted", False):
            checks.append(("VOLUME_UNENCRYPTED", "Block volume is not encrypted", "high", "encrypted=false", "Enable volume encryption."))
        if resource.resource_type == "iam_user" and not config.get("mfa_enabled", False):
            checks.append(("IAM_MFA", "IAM user does not have MFA enabled", "high", "mfa_enabled=false", "Require MFA for the user."))
        if not tags.get("owner") or not tags.get("environment"):
            checks.append(("TAGS_REQUIRED", "Resource is missing owner/environment tags", "medium", "owner/environment missing", "Apply the required tagging standard."))

        # HISF / HISO 10029:2022 & NZISM Health Security Framework Evaluation
        is_health_data = tags.get("data_classification") in {"phi", "health_info", "restricted"} or tags.get("domain") == "healthcare"

        if resource.resource_type in {"api_gateway", "http_endpoint"}:
            if not config.get("auth_enabled", True) or config.get("allow_unauthenticated", False):
                checks.append((
                    "HISF_API_AUTH_REQUIRED",
                    "Health API gateway allows unauthenticated access to health endpoints",
                    "critical",
                    "auth_enabled=false or allow_unauthenticated=true",
                    "Enforce mandatory token-based authentication (OAuth2/OIDC) and reject anonymous API access per HISO 10029."
                ))
            min_tls = str(config.get("min_tls_version", "1.2"))
            if min_tls in {"1.0", "1.1"} or config.get("allow_insecure_http", False):
                checks.append((
                    "NZISM_TLS_MODERN",
                    "Endpoint allows insecure or deprecated TLS/HTTP protocols",
                    "high",
                    f"min_tls_version={min_tls} allow_insecure_http={config.get('allow_insecure_http', False)}",
                    "Configure minimum TLS version 1.2 or 1.3 and disable unencrypted HTTP per NZISM Section 17.1."
                ))

        if is_health_data or resource.resource_type in {"health_data_store", "ehr_database"}:
            if not config.get("encrypted", False) or not config.get("kms_key_id"):
                checks.append((
                    "HISF_PHI_ENCRYPTION_REST",
                    "Health data repository lacks customer-managed key encryption at rest",
                    "critical",
                    f"encrypted={config.get('encrypted', False)} kms_key_id={config.get('kms_key_id')}",
                    "Enable envelope encryption with a dedicated customer-managed KMS key in compliance with HISO 10029 Section 9.4."
                ))
            if not config.get("audit_logging_enabled", False) or int(config.get("audit_retention_days", 0)) < 365:
                checks.append((
                    "HISF_AUDIT_LOGGING_RETENTION",
                    "Audit logging is disabled or retention period is under 365 days for health data",
                    "high",
                    f"audit_logging_enabled={config.get('audit_logging_enabled', False)} retention={config.get('audit_retention_days', 0)}",
                    "Enable comprehensive immutable access logging with >= 365 days retention per HISO 10029 Section 12.1."
                ))
            if not config.get("automated_backups", False) or not config.get("backup_immutability", False):
                checks.append((
                    "NZISM_BACKUP_PROTECTION",
                    "Health system lacks automated immutable backup protection",
                    "high",
                    f"automated_backups={config.get('automated_backups', False)} backup_immutability={config.get('backup_immutability', False)}",
                    "Enable automated daily snapshots with object lock/WORM immutability per NZISM Section 16.3."
                ))

        # NZX Modern Registry & FMA Financial Posture Evaluation
        checks.extend(evaluate_nzx_registry_posture(resource.resource_type, config, tags))

        for rule_id, title, severity, evidence, remediation in checks:
            finding = self.session.scalar(
                select(FindingRow).where(FindingRow.resource_id == resource.id, FindingRow.rule_id == rule_id)
            )
            if finding is None:
                finding = FindingRow(
                    resource_id=resource.id,
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    evidence=evidence,
                    remediation=remediation,
                )
                self.session.add(finding)
            elif finding.status == "resolved":
                finding.status = "open"
                finding.resolved_at = None

    def resolve_finding(self, finding_id: int, note: str) -> FindingRow:
        finding = self.session.get(FindingRow, finding_id)
        if finding is None:
            raise NotFoundError("finding not found")
        if finding.status == "resolved":
            raise ValidationError("finding already resolved")
        if not note.strip():
            raise ValidationError("resolution note is required")
        finding.status = "resolved"
        finding.resolved_at = datetime.now(timezone.utc)
        finding.evidence = f"{finding.evidence}; resolved: {note}"
        self._audit("finding_resolved", str(finding.id), note)
        self.session.commit()
        return finding

    def findings(self, status: str | None = None) -> list[FindingRow]:
        query = select(FindingRow).order_by(FindingRow.id)
        if status:
            query = query.where(FindingRow.status == status)
        return list(self.session.scalars(query).all())

    def summary(self) -> dict[str, Any]:
        findings = list(self.session.scalars(select(FindingRow)).all())
        by_severity = {severity: 0 for severity in SEVERITIES}
        for finding in findings:
            if finding.status == "open":
                by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        return {
            "accounts": self.session.scalar(select(AccountRow).count()) if False else len(self.session.scalars(select(AccountRow)).all()),
            "resources": len(self.session.scalars(select(ResourceRow)).all()),
            "findings_total": len(findings),
            "open_findings": sum(1 for f in findings if f.status == "open"),
            "open_by_severity": by_severity,
        }

    def audit(self) -> list[dict]:
        rows = self.session.scalars(select(AuditRow).order_by(AuditRow.id)).all()
        return [
            {"at": r.at.isoformat(), "action": r.action, "actor": r.actor, "reference": r.reference, "detail": r.detail}
            for r in rows
        ]
