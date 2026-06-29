"""Rule-based Kubernetes issue detection engine.

Scans log and event content for known Kubernetes failure patterns and returns
structured findings with severity, probable cause, and recommendations.
"""

import re
from typing import Optional


ISSUE_RULES = [
    {
        "issue_type": "CrashLoopBackOff",
        "keywords": [
            r"CrashLoopBackOff",
            r"Back-off restarting failed container",
            r"exited with code [1-9]",
        ],
        "severity": "Critical",
        "probable_causes": [
            "Application startup failure",
            "Missing environment variable or secret",
            "Wrong command or entrypoint in container spec",
            "ConfigMap or Secret misconfiguration",
            "Application dependency failure (database, service)",
        ],
        "explanation": (
            "The container keeps crashing and Kubernetes is repeatedly restarting it "
            "with increasing back-off delays. This typically indicates a fundamental "
            "application startup problem."
        ),
        "recommendation": (
            "Check pod logs with 'kubectl logs <pod> --previous', verify environment "
            "variables, ConfigMaps, Secrets, and application entrypoint configuration."
        ),
    },
    {
        "issue_type": "ImagePullBackOff",
        "keywords": [
            r"ImagePullBackOff",
            r"ErrImagePull",
            r"pull access denied",
            r"repository does not exist",
            r"unauthorized",
            r"manifest unknown",
        ],
        "severity": "Critical",
        "probable_causes": [
            "Wrong image name or tag",
            "Private registry authentication failure",
            "Missing imagePullSecret in pod spec",
            "ACR/ECR/GCR permission issue",
            "Image deleted or tag overwritten",
        ],
        "explanation": (
            "Kubernetes cannot pull the container image from the registry. The pod "
            "will remain in a pending/error state until the image is accessible."
        ),
        "recommendation": (
            "Verify the image name and tag, check registry credentials with "
            "'kubectl get secret', ensure imagePullSecrets are configured, and "
            "validate ACR/registry access."
        ),
    },
    {
        "issue_type": "OOMKilled",
        "keywords": [
            r"OOMKilled",
            r"exit code 137",
            r"memory limit",
            r"out of memory",
        ],
        "severity": "Critical",
        "probable_causes": [
            "Container memory limit set too low",
            "Application memory leak",
            "High traffic or load spike",
            "JVM/Node/Python memory configuration issue",
            "No resource limits defined",
        ],
        "explanation": (
            "The container exceeded its memory limit and was killed by the kernel "
            "OOM killer (exit code 137). This causes pod restarts and potential "
            "data loss for non-graceful shutdowns."
        ),
        "recommendation": (
            "Increase memory limits, profile application memory usage with "
            "'kubectl top pod', check for memory leaks, and configure proper "
            "resource requests/limits."
        ),
    },
    {
        "issue_type": "Readiness Probe Failed",
        "keywords": [
            r"Readiness probe failed",
            r"connection refused",
            r"HTTP probe failed",
            r"timeout",
        ],
        "severity": "High",
        "probable_causes": [
            "Application not ready to serve traffic",
            "Wrong readiness probe endpoint or port",
            "Application startup delay exceeds probe threshold",
            "Port mismatch between container and probe config",
            "Downstream service dependency unavailable",
        ],
        "explanation": (
            "The readiness probe is failing, which means Kubernetes will remove "
            "the pod from service endpoints. Traffic will not be routed to this "
            "pod until the probe passes."
        ),
        "recommendation": (
            "Verify the readiness endpoint, adjust initialDelaySeconds and "
            "timeoutSeconds, check application startup time, and validate "
            "the probe port matches the container port."
        ),
    },
    {
        "issue_type": "Liveness Probe Failed",
        "keywords": [
            r"Liveness probe failed",
            r"failed liveness probe",
            r"container will be restarted",
        ],
        "severity": "High",
        "probable_causes": [
            "Application health endpoint returning errors",
            "Probe timeout too low for the application",
            "CPU starvation causing slow responses",
            "Application deadlock or hang",
            "Wrong probe configuration (path, port, scheme)",
        ],
        "explanation": (
            "The liveness probe is failing, causing Kubernetes to restart the "
            "container. Frequent restarts indicate the application cannot "
            "maintain a healthy state."
        ),
        "recommendation": (
            "Increase probe timeoutSeconds and failureThreshold, verify the "
            "health endpoint, check CPU limits, and ensure the application "
            "handles health checks properly."
        ),
    },
    {
        "issue_type": "Pending Pod",
        "keywords": [
            r"Pending",
            r"FailedScheduling",
            r"insufficient cpu",
            r"insufficient memory",
            r"node affinity",
            r"taint",
            r"toleration",
        ],
        "severity": "High",
        "probable_causes": [
            "Insufficient cluster CPU or memory resources",
            "Node selector or affinity mismatch",
            "Taints and tolerations mismatch",
            "PersistentVolumeClaim not bound",
            "ResourceQuota limits reached",
        ],
        "explanation": (
            "The pod cannot be scheduled to any node. It will remain in Pending "
            "state until sufficient resources are available or scheduling "
            "constraints are resolved."
        ),
        "recommendation": (
            "Check node resources with 'kubectl top nodes', review node selectors "
            "and taints, verify PVC status, and check ResourceQuota with "
            "'kubectl get resourcequota'."
        ),
    },
    {
        "issue_type": "Node Pressure",
        "keywords": [
            r"MemoryPressure",
            r"DiskPressure",
            r"PIDPressure",
            r"node had condition",
        ],
        "severity": "High",
        "probable_causes": [
            "Node resource exhaustion (memory, disk, PIDs)",
            "Too many pods scheduled on the node",
            "Disk full from logs or temp files",
            "Cluster autoscaler not scaling fast enough",
            "Resource requests not configured correctly",
        ],
        "explanation": (
            "One or more nodes are under resource pressure. Kubernetes may start "
            "evicting pods from affected nodes to reclaim resources."
        ),
        "recommendation": (
            "Check node status with 'kubectl describe node', review pod resource "
            "requests, enable cluster autoscaler, clean up disk space, and "
            "consider adding nodes to the cluster."
        ),
    },
    {
        "issue_type": "DNS Failure",
        "keywords": [
            r"Name or service not known",
            r"temporary failure in name resolution",
            r"DNS lookup failed",
            r"connection timed out",
        ],
        "severity": "Medium",
        "probable_causes": [
            "CoreDNS pods not running or unhealthy",
            "NetworkPolicy blocking DNS traffic",
            "Wrong service name in application config",
            "Namespace mismatch in service discovery",
            "External DNS or upstream network issue",
        ],
        "explanation": (
            "DNS resolution is failing inside the cluster. Applications cannot "
            "resolve service names, which breaks inter-service communication "
            "and external API calls."
        ),
        "recommendation": (
            "Check CoreDNS pods with 'kubectl get pods -n kube-system', test "
            "DNS from inside a pod with 'nslookup', verify service names and "
            "namespaces, and review NetworkPolicies."
        ),
    },
]


def analyze(files: list[dict]) -> list[dict]:
    """Analyze a list of log/event files for Kubernetes issues.

    Args:
        files: List of file dicts from log_loader (must have 'file_name' and 'content').

    Returns:
        List of finding dicts with issue_type, severity, matched_keyword, etc.
    """
    findings = []

    for file_info in files:
        content = file_info.get("content", "")
        file_name = file_info.get("file_name", "unknown")

        for rule in ISSUE_RULES:
            matched_keyword = _find_keyword_match(content, rule["keywords"])
            if not matched_keyword:
                continue

            findings.append({
                "file_name": file_name,
                "file_type": file_info.get("file_type", "log"),
                "issue_type": rule["issue_type"],
                "severity": rule["severity"],
                "matched_keyword": matched_keyword,
                "probable_causes": rule["probable_causes"],
                "explanation": rule["explanation"],
                "recommendation": rule["recommendation"],
            })

    findings.sort(key=lambda f: _severity_rank(f["severity"]))
    return findings


def _find_keyword_match(content: str, keywords: list[str]) -> Optional[str]:
    """Return the first keyword that matches in the content (case-insensitive)."""
    for keyword in keywords:
        if re.search(keyword, content, re.IGNORECASE):
            return keyword
    return None


def _severity_rank(severity: str) -> int:
    """Lower number = higher priority for sorting."""
    ranks = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return ranks.get(severity, 99)
