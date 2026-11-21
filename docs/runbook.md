# Operations & Rollback Runbook: cloud-security-posture

## 1. System Overview & SLOs
- **Service Name:** cloud-security-posture
- **Availability Target:** 99.95% uptime
- **Latency SLO:** p95 latency < 50ms for posture evaluation and detection-as-code event processing; p99 latency < 120ms.

## 2. Health & Liveness Checks
- Liveness probe: `GET /health` (returns HTTP 200 with status "ok").
- Readiness probe: `GET /ready` (checks database connection pool and migration status).

## 3. Incident Triage & Alerts
1. **High Alert Rate:** Check `AlertTriagePipeline` metrics in Datadog/Grafana. If alert velocity exceeds 50 alerts/min for a single entity, trigger automated session quarantine.
2. **Database Connectivity Degradation:** If DB latency exceeds 100ms, scale read replicas and verify pool exhaustion.

## 4. Rollback Procedure
If a bad release or detection rule causes regression or service degradation:
1. Identify the previous stable release commit or Docker container tag (e.g. `v1.0.0`).
2. Rollback deployment via Helm / ArgoCD:
   ```bash
   helm rollback cloud-security-posture <previous-revision>
   ```
3. To rollback database migrations:
   ```bash
   alembic downgrade -1
   ```
4. Verify rollback success:
   ```bash
   bash scripts/smoke.sh
   ```
5. Notify incident commander in #security-ops that rollback is complete.
