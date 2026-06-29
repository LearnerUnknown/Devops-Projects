"""Unit tests for the Kubernetes rule-based analyzer."""

import pytest
from app.k8s_rule_analyzer import analyze


def _make_file(name: str, content: str, file_type: str = "log") -> dict:
    return {
        "file_name": name,
        "file_path": f"/test/{name}",
        "file_type": file_type,
        "content": content,
    }


class TestCrashLoopBackOff:
    def test_detects_crashloopbackoff_keyword(self):
        files = [_make_file("app.log", "Warning: CrashLoopBackOff for container web")]
        findings = analyze(files)
        assert len(findings) >= 1
        assert any(f["issue_type"] == "CrashLoopBackOff" for f in findings)

    def test_detects_backoff_restarting(self):
        files = [_make_file("pod.log", "Back-off restarting failed container api")]
        findings = analyze(files)
        assert any(f["issue_type"] == "CrashLoopBackOff" for f in findings)

    def test_severity_is_critical(self):
        files = [_make_file("crash.log", "CrashLoopBackOff detected")]
        findings = analyze(files)
        crash_findings = [f for f in findings if f["issue_type"] == "CrashLoopBackOff"]
        assert crash_findings[0]["severity"] == "Critical"


class TestImagePullBackOff:
    def test_detects_imagepullbackoff(self):
        files = [_make_file("img.log", "Error: ImagePullBackOff for image nginx:latest")]
        findings = analyze(files)
        assert any(f["issue_type"] == "ImagePullBackOff" for f in findings)

    def test_detects_errimagepull(self):
        files = [_make_file("img.log", "ErrImagePull: unable to pull image")]
        findings = analyze(files)
        assert any(f["issue_type"] == "ImagePullBackOff" for f in findings)

    def test_detects_pull_access_denied(self):
        files = [_make_file("img.log", "pull access denied for private-repo/app")]
        findings = analyze(files)
        assert any(f["issue_type"] == "ImagePullBackOff" for f in findings)

    def test_severity_is_critical(self):
        files = [_make_file("img.log", "ImagePullBackOff")]
        findings = analyze(files)
        img_findings = [f for f in findings if f["issue_type"] == "ImagePullBackOff"]
        assert img_findings[0]["severity"] == "Critical"


class TestOOMKilled:
    def test_detects_oomkilled(self):
        files = [_make_file("oom.log", "Container was OOMKilled")]
        findings = analyze(files)
        assert any(f["issue_type"] == "OOMKilled" for f in findings)

    def test_detects_exit_code_137(self):
        files = [_make_file("oom.log", "Container terminated with exit code 137")]
        findings = analyze(files)
        assert any(f["issue_type"] == "OOMKilled" for f in findings)

    def test_severity_is_critical(self):
        files = [_make_file("oom.log", "OOMKilled")]
        findings = analyze(files)
        oom_findings = [f for f in findings if f["issue_type"] == "OOMKilled"]
        assert oom_findings[0]["severity"] == "Critical"


class TestReadinessProbe:
    def test_detects_readiness_probe_failed(self):
        files = [_make_file("probe.log", "Readiness probe failed: HTTP probe failed")]
        findings = analyze(files)
        assert any(f["issue_type"] == "Readiness Probe Failed" for f in findings)

    def test_detects_connection_refused(self):
        files = [_make_file("probe.log", "Readiness probe failed: connection refused")]
        findings = analyze(files)
        assert any(f["issue_type"] == "Readiness Probe Failed" for f in findings)

    def test_severity_is_high(self):
        files = [_make_file("probe.log", "Readiness probe failed")]
        findings = analyze(files)
        probe_findings = [f for f in findings if f["issue_type"] == "Readiness Probe Failed"]
        assert probe_findings[0]["severity"] == "High"


class TestPendingPod:
    def test_detects_failedscheduling(self):
        files = [_make_file("sched.log", "FailedScheduling: 0/3 nodes are available")]
        findings = analyze(files)
        assert any(f["issue_type"] == "Pending Pod" for f in findings)

    def test_detects_insufficient_memory(self):
        files = [_make_file("sched.log", "insufficient memory for pod request")]
        findings = analyze(files)
        assert any(f["issue_type"] == "Pending Pod" for f in findings)

    def test_severity_is_high(self):
        files = [_make_file("sched.log", "FailedScheduling")]
        findings = analyze(files)
        pending_findings = [f for f in findings if f["issue_type"] == "Pending Pod"]
        assert pending_findings[0]["severity"] == "High"


class TestDNSFailure:
    def test_detects_name_resolution_failure(self):
        files = [_make_file("dns.log", "temporary failure in name resolution")]
        findings = analyze(files)
        assert any(f["issue_type"] == "DNS Failure" for f in findings)

    def test_detects_dns_lookup_failed(self):
        files = [_make_file("dns.log", "DNS lookup failed for service.namespace")]
        findings = analyze(files)
        assert any(f["issue_type"] == "DNS Failure" for f in findings)

    def test_severity_is_medium(self):
        files = [_make_file("dns.log", "temporary failure in name resolution")]
        findings = analyze(files)
        dns_findings = [f for f in findings if f["issue_type"] == "DNS Failure"]
        assert dns_findings[0]["severity"] == "Medium"


class TestNoIssues:
    def test_clean_log_returns_no_findings(self):
        files = [_make_file("clean.log", "INFO: Application started successfully\nINFO: Healthy")]
        findings = analyze(files)
        assert len(findings) == 0


class TestMultipleIssues:
    def test_detects_multiple_issues_in_one_file(self):
        content = "CrashLoopBackOff detected\nOOMKilled exit code 137"
        files = [_make_file("multi.log", content)]
        findings = analyze(files)
        issue_types = {f["issue_type"] for f in findings}
        assert "CrashLoopBackOff" in issue_types
        assert "OOMKilled" in issue_types

    def test_findings_sorted_by_severity(self):
        content = "DNS lookup failed\nCrashLoopBackOff\nReadiness probe failed"
        files = [_make_file("mixed.log", content)]
        findings = analyze(files)
        severities = [f["severity"] for f in findings]
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        ranks = [severity_order[s] for s in severities]
        assert ranks == sorted(ranks)


class TestFindingStructure:
    def test_finding_has_required_fields(self):
        files = [_make_file("test.log", "CrashLoopBackOff")]
        findings = analyze(files)
        assert len(findings) >= 1
        finding = findings[0]
        required_keys = {
            "file_name", "file_type", "issue_type", "severity",
            "matched_keyword", "probable_causes", "explanation", "recommendation",
        }
        assert required_keys.issubset(finding.keys())
