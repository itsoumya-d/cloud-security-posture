"""Kubernetes workload security and operational admission posture evaluator."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PostureSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_PENALTIES = {
    PostureSeverity.CRITICAL: 35,
    PostureSeverity.HIGH: 20,
    PostureSeverity.MEDIUM: 10,
    PostureSeverity.LOW: 5,
    PostureSeverity.INFO: 0,
}


@dataclass(frozen=True)
class PostureFinding:
    rule_id: str
    title: str
    severity: PostureSeverity
    container: str | None
    description: str
    remediation: str


@dataclass
class WorkloadPostureReport:
    workload_name: str
    workload_kind: str
    namespace: str
    score: int
    passed: bool
    findings: list[PostureFinding] = field(default_factory=list)

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in (PostureSeverity.CRITICAL, PostureSeverity.HIGH) for f in self.findings)


def _extract_pod_spec(manifest: dict[str, Any]) -> dict[str, Any]:
    kind = manifest.get("kind", "")
    return manifest.get("spec", {}) if kind == "Pod" else manifest.get("spec", {}).get("template", {}).get("spec", {})


def evaluate_workload_manifest(manifest: dict[str, Any]) -> WorkloadPostureReport:
    """Evaluates a raw Kubernetes manifest dictionary for posture compliance."""
    metadata = manifest.get("metadata", {})
    name = metadata.get("name", "unnamed-workload")
    namespace = metadata.get("namespace", "default")
    kind = manifest.get("kind", "Unknown")

    findings: list[PostureFinding] = []
    spec = _extract_pod_spec(manifest)
    containers: list[dict[str, Any]] = spec.get("containers", [])
    pod_sec = spec.get("securityContext", {})

    if kind in ("Deployment", "StatefulSet"):
        replicas = manifest.get("spec", {}).get("replicas", 1)
        if replicas < 2 and namespace != "test":
            findings.append(PostureFinding(
                rule_id="K8S-OPS-003",
                title="Single Replica Deployment",
                severity=PostureSeverity.LOW,
                container=None,
                description=f"Workload '{name}' specifies replicas={replicas}, lacking HA failover.",
                remediation="Set spec.replicas to 2 or greater, or configure an HPA.",
            ))

    for c in containers:
        c_name = c.get("name", "unknown")
        c_sec = c.get("securityContext", {})

        if c_sec.get("privileged") is True:
            findings.append(PostureFinding(
                rule_id="K8S-SEC-001",
                title="Privileged Container Execution",
                severity=PostureSeverity.CRITICAL,
                container=c_name,
                description=f"Container '{c_name}' runs in privileged mode with full host access.",
                remediation="Set securityContext.privileged to false and use granular Linux capabilities.",
            ))

        if c_sec.get("readOnlyRootFilesystem") is not True:
            findings.append(PostureFinding(
                rule_id="K8S-SEC-002",
                title="Root Filesystem Not Read-Only",
                severity=PostureSeverity.HIGH,
                container=c_name,
                description=f"Container '{c_name}' allows writes to its root filesystem.",
                remediation="Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for scratch.",
            ))

        run_as_non_root = c_sec.get("runAsNonRoot") or pod_sec.get("runAsNonRoot")
        run_as_user = c_sec.get("runAsUser") or pod_sec.get("runAsUser")
        if not (run_as_non_root is True or (isinstance(run_as_user, int) and run_as_user > 0)):
            findings.append(PostureFinding(
                rule_id="K8S-SEC-003",
                title="Container May Run As Root User",
                severity=PostureSeverity.HIGH,
                container=c_name,
                description=f"Container '{c_name}' does not enforce runAsNonRoot or non-zero UID.",
                remediation="Specify securityContext.runAsNonRoot: true and provide a non-zero runAsUser.",
            ))

        if c_sec.get("allowPrivilegeEscalation") is not False:
            findings.append(PostureFinding(
                rule_id="K8S-SEC-004",
                title="Privilege Escalation Permitted",
                severity=PostureSeverity.HIGH,
                container=c_name,
                description=f"Container '{c_name}' allows child processes to gain elevated privileges.",
                remediation="Set securityContext.allowPrivilegeEscalation: false.",
            ))

        caps = c_sec.get("capabilities", {})
        if "ALL" not in [str(x).upper() for x in caps.get("drop", [])]:
            findings.append(PostureFinding(
                rule_id="K8S-SEC-005",
                title="Linux Capabilities Not Dropped",
                severity=PostureSeverity.MEDIUM,
                container=c_name,
                description=f"Container '{c_name}' does not drop ALL Linux kernel capabilities.",
                remediation="Add securityContext.capabilities.drop: ['ALL'].",
            ))

        resources = c.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})

        if not (limits.get("cpu") and limits.get("memory")):
            findings.append(PostureFinding(
                rule_id="K8S-RES-001",
                title="Missing Resource Limits",
                severity=PostureSeverity.HIGH,
                container=c_name,
                description=f"Container '{c_name}' has incomplete resource limits (requires cpu & memory).",
                remediation="Define resources.limits.cpu and resources.limits.memory.",
            ))

        if not (requests.get("cpu") and requests.get("memory")):
            findings.append(PostureFinding(
                rule_id="K8S-RES-002",
                title="Missing Resource Requests",
                severity=PostureSeverity.MEDIUM,
                container=c_name,
                description=f"Container '{c_name}' has incomplete resource requests (requires cpu & memory).",
                remediation="Define resources.requests.cpu and resources.requests.memory for scheduling.",
            ))

        if kind not in ("Job", "CronJob"):
            if not c.get("livenessProbe"):
                findings.append(PostureFinding(
                    rule_id="K8S-OPS-001",
                    title="Missing Liveness Probe",
                    severity=PostureSeverity.MEDIUM,
                    container=c_name,
                    description=f"Container '{c_name}' does not specify a livenessProbe.",
                    remediation="Define a container livenessProbe for lifecycle recovery.",
                ))
            if not c.get("readinessProbe"):
                findings.append(PostureFinding(
                    rule_id="K8S-OPS-002",
                    title="Missing Readiness Probe",
                    severity=PostureSeverity.MEDIUM,
                    container=c_name,
                    description=f"Container '{c_name}' does not specify a readinessProbe.",
                    remediation="Define a container readinessProbe to prevent premature ingress traffic.",
                ))

    total_penalty = sum(SEVERITY_PENALTIES[f.severity] for f in findings)
    score = max(0, 100 - total_penalty)
    passed = score >= 80 and not any(
        f.severity in (PostureSeverity.CRITICAL, PostureSeverity.HIGH) for f in findings
    )

    return WorkloadPostureReport(
        workload_name=name,
        workload_kind=kind,
        namespace=namespace,
        score=score,
        passed=passed,
        findings=findings,
    )
