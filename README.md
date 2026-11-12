# cloud-security-posture

[![ci](https://github.com/itsoumya-d/cloud-security-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/itsoumya-d/cloud-security-posture/actions/workflows/ci.yml)

A production-oriented cloud security posture service:

- AWS/Azure/GCP account registration.
- Resource snapshot ingestion for buckets, security groups, volumes, IAM users
  and other resource types.
- CIS-style checks: public storage, missing encryption, open admin ports,
  missing MFA and required tags.
- Health Information Security Framework (HISO 10029:2022 / HISF) and NZISM
  compliance evaluations: unauthenticated API gateway detection, mandatory
  token auth, modern TLS (>=1.2/1.3) enforcement, PHI customer-managed key
  encryption at rest, immutable access audit logging (>=365 days retention),
  and WORM backup protection.
- Deduplicated findings with severity, evidence and remediation guidance.
- Resolution workflow; findings reopen if a later snapshot regresses.
- Security summary and persisted audit trail.
- API-key RBAC (`viewer`, `analyst`, `admin`).
- PostgreSQL/SQLite, Alembic migrations, Docker and CI.

This is a real backend service, not a dashboard prototype. It does **not** claim
live AWS/Azure/GCP API connectors; resource snapshots are supplied by the
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

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
export API_KEYS='{"dev-admin":"admin","dev-analyst":"analyst","dev-viewer":"viewer"}'
alembic upgrade head
uvicorn cloudposture.api:app --reload
```

## Tests

```bash
pytest
```

Covers account validation, clean/unsafe resources, open admin ports, volume
encryption, MFA, tags, deduplication, reopening, resolution, summary and audit.

## License

MIT
