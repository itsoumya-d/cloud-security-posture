"""Unit tests for Kubernetes workload security and operational posture evaluator."""

from cloudposture.k8s_workload_posture import (
    PostureSeverity,
    evaluate_workload_manifest,
)


def test_fully_compliant_deployment():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "telemetry-router", "namespace": "production"},
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
                    "containers": [{
                        "name": "router",
                        "image": "registry.internal/telemetry:v1.2.0",
                        "securityContext": {
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "privileged": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                        },
                        "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                        "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                    }],
                }
            },
        },
    }

    report = evaluate_workload_manifest(manifest)
    assert report.workload_name == "telemetry-router"
    assert report.score == 100
    assert report.passed is True
    assert len(report.findings) == 0
    assert report.has_critical_or_high is False


def test_privileged_workload_fails_admission():
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "unsafe-daemon", "namespace": "default"},
        "spec": {
            "replicas": 2,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "unsafe",
                        "image": "busybox:latest",
                        "securityContext": {
                            "privileged": True,
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "runAsNonRoot": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}, "requests": {"cpu": "50m", "memory": "32Mi"}},
                        "livenessProbe": {"tcpSocket": {"port": 80}},
                        "readinessProbe": {"tcpSocket": {"port": 80}},
                    }]
                }
            },
        },
    }

    report = evaluate_workload_manifest(manifest)
    assert report.passed is False
    assert report.has_critical_or_high is True
    assert any(f.rule_id == "K8S-SEC-001" and f.severity == PostureSeverity.CRITICAL for f in report.findings)


def test_missing_probes_and_resources_flags_findings():
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "ad-hoc-worker", "namespace": "staging"},
        "spec": {
            "containers": [
                {
                    "name": "worker",
                    "image": "python:3.12-slim",
                    "securityContext": {
                        "readOnlyRootFilesystem": False,
                        "allowPrivilegeEscalation": True,
                    },
                }
            ]
        },
    }

    report = evaluate_workload_manifest(manifest)
    assert report.passed is False
    rule_ids = {f.rule_id for f in report.findings}
    assert {"K8S-SEC-002", "K8S-SEC-003", "K8S-SEC-004", "K8S-RES-001", "K8S-OPS-001"}.issubset(rule_ids)
