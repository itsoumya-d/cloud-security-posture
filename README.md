# cloud-security-posture

[![ci](https://github.com/itsoumya-d/cloud-security-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/itsoumya-d/cloud-security-posture/actions/workflows/ci.yml)

A production-oriented cloud security posture and detection-as-code service:

- **Detection-as-Code Engine:** High-signal cloud identity detection rules, MITRE ATT&CK mapping, rule lifecycle controls (`experimental`, `staging`, `production`), and suppression filters.
- **Rule Verification Harness:** Deterministic pre-rollout test harness validating expected positive and negative telemetry matches before production promotion.
- **Automated Alert Triage & Enrichment:** Context enrichment across entity history, asset criticality profiling, open vulnerability correlation, composite risk scoring (0–100), and automated containment runbook generation.
- **LLM-Assisted Investigation Synthesis:** Structured triage briefings summarizing threat telemetry, adversary TTPs, and blast radius analysis with deterministic fallback.
- **Cloud Security Posture Management (CSPM):** AWS/Azure/GCP account registration, resource snapshot ingestion, CIS-style posture audits, and compliance evaluation.
- **Security Frameworks:** CIS benchmarks, HISO 10029:2022 / NZISM health information compliance, and strict API-key RBAC (`viewer`, `analyst`, `admin`).
- **Production Rigor:** PostgreSQL/SQLite storage, Alembic migrations, Docker containerization, and automated GitHub Actions CI matrix with 33 passing unit tests.

This is a real backend service, not a dashboard prototype. It does **not** claim
live AWS/Azure/GCP API connectors; resource snapshots and telemetry events are supplied by the
operator/collector and evaluated by the service.

## API

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness |
| GET | `/ready` | none | Database readiness |
| POST | `/accounts` | admin | Register a cloud account |
| POST | `/accounts/{id}/sync` | analyst | Ingest a resource snapshot |
| GET | `/findings` | viewer | List findings, optional `?status=` |
| POST | `/findings/{id}/resolve` | analyst | Resolve a finding |
| GET | `/summary` | viewer | Posture summary |
| GET | `/audit` | admin | Audit trail |

Send `X-API-Key: <key>` on protected requests.

## Detection-as-Code & Triage Architecture

```python
from cloudposture import (
    DetectionEngine,
    AlertTriagePipeline,
    build_aws_console_login_without_mfa_rule,
    build_anomalous_iam_assume_role_rule,
)

# Initialize engine and register production-ready rules
engine = DetectionEngine()
engine.register_rule(build_aws_console_login_without_mfa_rule())
engine.register_rule(build_anomalous_iam_assume_role_rule())

# Pre-rollout harness verification
engine.test_rule_harness("DET-AWS-001")  # [] (zero failures)

# Evaluate live cloud identity telemetry
alerts = engine.evaluate_event(cloudtrail_event)

# Triage, correlate posture findings, and generate containment runbook
triage = AlertTriagePipeline()
enriched = triage.enrich_alert(alerts[0], historical_alerts=[...])
print(enriched.risk_score, enriched.investigation_summary, enriched.recommended_actions)
```

## Core Capabilities

- **Protective Security Requirements (PSR) & NZISM Architecture Governance** (`cloudposture.psr_security_governance`): Evaluates cloud architecture blueprints against NZISM Chapter 14/16/18 and PSR core controls (TLS 1.3 transit encryption, zero-trust MFA boundaries, customer-managed KMS encryption, and immutable audit telemetry), calculating compliance scores and generating prescriptive remediation runbooks.
- **Automated Cloud Posture & Detection Engine**: Continuous CIS benchmark evaluation, IAM privilege auditing, and threat detection.

## Run locally & Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
export API_KEYS='{"dev-admin":"admin","dev-analyst":"analyst","dev-viewer":"viewer"}'
alembic upgrade head
pytest  # 33 passed
```
