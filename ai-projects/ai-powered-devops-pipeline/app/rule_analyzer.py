"""
Rule-Based DevOps Analyzer

Performs static analysis on DevOps configuration files using predefined
rules covering security, reliability, CI/CD best practices, and
infrastructure-as-code standards.
"""

import re
from typing import List, Dict


def analyze_file(file_name: str, file_type: str, content: str) -> List[Dict[str, str]]:
    """Route analysis to the appropriate checker based on file type."""
    dispatch = {
        "GitHub Actions Workflow": _analyze_github_actions,
        "GitLab CI/CD Pipeline": _analyze_gitlab_ci,
        "Dockerfile": _analyze_dockerfile,
        "Terraform Configuration": _analyze_terraform,
        "Kubernetes Manifest": _analyze_kubernetes,
        "Helm Values": _analyze_helm,
        "Ansible Playbook": _analyze_ansible,
    }

    checker = dispatch.get(file_type)
    if not checker:
        return []

    return checker(file_name, content)


def _finding(file_name: str, file_type: str, category: str,
             severity: str, issue: str, recommendation: str) -> Dict[str, str]:
    """Create a standardized finding dictionary."""
    return {
        "file_name": file_name,
        "file_type": file_type,
        "category": category,
        "severity": severity,
        "issue": issue,
        "recommendation": recommendation,
    }


# ── GitHub Actions ──────────────────────────────────────────────────────────

def _analyze_github_actions(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "GitHub Actions Workflow"
    lower = content.lower()

    if "build" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "High",
            "No build step detected in workflow",
            "Add a build job to compile, bundle, or package your application"))

    if "test" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "High",
            "No test step detected in workflow",
            "Add a test job to run unit, integration, or end-to-end tests"))

    security_keywords = ["security", "scan", "sast", "dast", "snyk", "trivy",
                         "codeql", "fortify", "black.duck", "blackduck",
                         "sonarqube", "semgrep", "checkov"]
    if not any(kw in lower for kw in security_keywords):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "No security scanning step detected",
            "Integrate a security scanner (CodeQL, Trivy, Snyk, Fortify, or Black Duck)"))

    if "deploy" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "Medium",
            "No deployment step detected",
            "Add a deployment job targeting your staging and production environments"))

    if "environment:" not in lower or "manual" not in lower:
        if "deploy" in lower and "approval" not in lower:
            findings.append(_finding(
                file_name, ft, "CI/CD", "High",
                "Production deployment may lack manual approval gate",
                "Use GitHub Environments with required reviewers for production deploys"))

    if "artifacts" not in lower and "upload-artifact" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "Low",
            "No artifact upload configured",
            "Use actions/upload-artifact to persist build outputs and test reports"))

    if _has_hardcoded_secrets(content):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "Possible hardcoded secrets or passwords detected",
            "Use GitHub Secrets (${{ secrets.* }}) instead of hardcoded credentials"))

    return findings


# ── GitLab CI/CD ────────────────────────────────────────────────────────────

def _analyze_gitlab_ci(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "GitLab CI/CD Pipeline"
    lower = content.lower()

    if "build" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "High",
            "No build stage detected",
            "Add a build stage to compile or package your application"))

    if "test" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "High",
            "No test stage detected",
            "Add a test stage with unit and integration tests"))

    security_keywords = ["security", "scan", "sast", "dast", "container_scanning",
                         "dependency_scanning", "trivy", "fortify", "blackduck"]
    if not any(kw in lower for kw in security_keywords):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "No security scanning stage detected",
            "Enable GitLab SAST/DAST or integrate Trivy, Fortify, or Black Duck scanning"))

    if "deploy" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "Medium",
            "No deployment stage detected",
            "Add deploy stages for staging and production environments"))

    if "when: manual" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "High",
            "No manual approval gate for production deployment",
            "Add 'when: manual' to production deploy jobs for controlled releases"))

    if "artifacts:" not in lower:
        findings.append(_finding(
            file_name, ft, "CI/CD", "Low",
            "No artifacts configuration found",
            "Configure artifacts to preserve build outputs, logs, and test reports"))

    if _has_hardcoded_secrets(content):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "Possible hardcoded secrets or passwords detected",
            "Use GitLab CI/CD Variables instead of hardcoded credentials"))

    return findings


# ── Dockerfile ──────────────────────────────────────────────────────────────

def _analyze_dockerfile(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "Dockerfile"
    lower = content.lower()

    if re.search(r"from\s+\S+:latest", lower):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "Base image uses the 'latest' tag",
            "Pin a specific image version (e.g., python:3.11-slim) for reproducibility"))

    from_lines = re.findall(r"from\s+(\S+)", lower)
    for img in from_lines:
        if ":" not in img or img.endswith(":latest"):
            continue
        if img.count(":") == 0:
            findings.append(_finding(
                file_name, ft, "Security", "Medium",
                f"Image '{img}' does not have a pinned tag",
                "Always pin image versions to ensure reproducible builds"))

    if "user " not in lower and "user=" not in lower:
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "No non-root USER instruction found",
            "Add a USER directive to run the container as a non-root user"))

    if "healthcheck" not in lower:
        findings.append(_finding(
            file_name, ft, "Reliability", "Medium",
            "No HEALTHCHECK instruction found",
            "Add HEALTHCHECK to allow orchestrators to monitor container health"))

    unnecessary_patterns = ["apt-get install", "yum install", "apk add"]
    for pattern in unnecessary_patterns:
        if pattern in lower and "--no-install-recommends" not in lower:
            findings.append(_finding(
                file_name, ft, "Security", "Low",
                "Package installation without --no-install-recommends",
                "Use --no-install-recommends to minimize installed packages and attack surface"))
            break

    return findings


# ── Terraform ───────────────────────────────────────────────────────────────

def _analyze_terraform(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "Terraform Configuration"
    lower = content.lower()

    if "backend" not in lower and file_name.endswith(".tf"):
        findings.append(_finding(
            file_name, ft, "Reliability", "High",
            "No backend configuration for remote state storage",
            "Configure a remote backend (e.g., azurerm, s3) for state management"))

    if "required_providers" not in lower and "version" not in lower:
        findings.append(_finding(
            file_name, ft, "Reliability", "Medium",
            "Provider version is not pinned",
            "Pin provider versions in required_providers to prevent breaking changes"))

    if "variable" not in lower and "var." not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Medium",
            "No input variables detected",
            "Use variables for configurable values to improve reusability"))

    if "tags" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Medium",
            "No resource tags found",
            "Add tags for cost tracking, ownership, and environment identification"))

    if _has_hardcoded_secrets(content):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "Possible hardcoded sensitive values detected",
            "Use Terraform variables marked as sensitive or reference Azure Key Vault"))

    resource_names = re.findall(r'resource\s+"[^"]+"\s+"([^"]+)"', content)
    if resource_names:
        naming_patterns = set()
        for name in resource_names:
            if "_" in name:
                naming_patterns.add("snake_case")
            elif "-" in name:
                naming_patterns.add("kebab-case")
            else:
                naming_patterns.add("other")
        if len(naming_patterns) > 1:
            findings.append(_finding(
                file_name, ft, "Best Practice", "Low",
                "Inconsistent resource naming convention detected",
                "Adopt a consistent naming convention (e.g., snake_case) across all resources"))

    return findings


# ── Kubernetes ──────────────────────────────────────────────────────────────

def _analyze_kubernetes(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "Kubernetes Manifest"
    lower = content.lower()

    if "resources:" not in lower:
        findings.append(_finding(
            file_name, ft, "Reliability", "High",
            "No resource requests or limits defined",
            "Set CPU and memory requests/limits to prevent resource contention"))

    if "livenessprobe" not in lower:
        findings.append(_finding(
            file_name, ft, "Reliability", "High",
            "No livenessProbe configured",
            "Add a livenessProbe so Kubernetes can restart unhealthy pods"))

    if "readinessprobe" not in lower:
        findings.append(_finding(
            file_name, ft, "Reliability", "High",
            "No readinessProbe configured",
            "Add a readinessProbe to prevent routing traffic to unready pods"))

    replicas_match = re.search(r"replicas:\s*(\d+)", content)
    if replicas_match and int(replicas_match.group(1)) <= 1:
        findings.append(_finding(
            file_name, ft, "Reliability", "Medium",
            "Replica count is 1 — no high availability",
            "Set replicas to at least 2 for production workloads"))

    if re.search(r"image:\s*\S+:latest", lower):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "Container image uses the 'latest' tag",
            "Pin a specific image tag for reproducible deployments"))

    if "namespace:" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Medium",
            "No namespace defined",
            "Specify a namespace to isolate workloads and apply RBAC policies"))

    return findings


# ── Helm ────────────────────────────────────────────────────────────────────

def _analyze_helm(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "Helm Values"
    lower = content.lower()

    if "repository:" not in lower or "tag:" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Medium",
            "Image repository or tag not clearly defined",
            "Define image.repository and image.tag for explicit version control"))

    if "resources:" not in lower:
        findings.append(_finding(
            file_name, ft, "Reliability", "High",
            "No resource requests or limits configured in Helm values",
            "Set resources.requests and resources.limits for predictable scheduling"))

    if "type:" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Low",
            "Service type not defined in values",
            "Specify service.type (ClusterIP, LoadBalancer, etc.) explicitly"))

    if "env:" not in lower and "environment:" not in lower and "config:" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Low",
            "Environment values are not clearly separated",
            "Use a dedicated env or config section to manage environment-specific values"))

    return findings


# ── Ansible ─────────────────────────────────────────────────────────────────

def _analyze_ansible(file_name: str, content: str) -> List[Dict[str, str]]:
    findings = []
    ft = "Ansible Playbook"
    lower = content.lower()

    if "{{" not in content:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Medium",
            "No Jinja2 variables detected",
            "Use variables ({{ var }}) for configurable and reusable playbooks"))

    if "become:" in lower and "become_user:" not in lower:
        findings.append(_finding(
            file_name, ft, "Security", "Medium",
            "become is used without specifying become_user",
            "Explicitly set become_user to control privilege escalation scope"))

    if _has_hardcoded_secrets(content):
        findings.append(_finding(
            file_name, ft, "Security", "High",
            "Possible hardcoded passwords or secrets detected",
            "Use Ansible Vault or external secret managers for sensitive data"))

    if "handlers:" not in lower and "notify:" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Low",
            "No handlers detected",
            "Use handlers for actions that should only run on change (e.g., restart services)"))

    if "name:" not in lower:
        findings.append(_finding(
            file_name, ft, "Best Practice", "Medium",
            "Tasks are missing descriptive names",
            "Add meaningful 'name' fields to every task for clarity and debugging"))

    return findings


# ── Shared Utilities ────────────────────────────────────────────────────────

def _has_hardcoded_secrets(content: str) -> bool:
    """Check for patterns that suggest hardcoded credentials."""
    patterns = [
        r'password\s*[:=]\s*["\'][^${\s][^"\']{3,}',
        r'secret\s*[:=]\s*["\'][^${\s][^"\']{3,}',
        r'api[_-]?key\s*[:=]\s*["\'][^${\s][^"\']{3,}',
        r'token\s*[:=]\s*["\'][^${\s][^"\']{3,}',
        r'conn.*string\s*[:=]\s*["\'][^${\s][^"\']{3,}',
    ]
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def analyze_all(files: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Run rule-based analysis on all loaded files and return combined findings."""
    all_findings = []
    for f in files:
        findings = analyze_file(f["file_name"], f["file_type"], f["content"])
        all_findings.extend(findings)
    return all_findings
