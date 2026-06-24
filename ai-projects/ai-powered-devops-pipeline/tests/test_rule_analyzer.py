"""
Unit tests for the rule_analyzer module.

Validates that the rule engine correctly detects common DevOps
misconfigurations across Docker, Kubernetes, Terraform, and CI/CD files.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from rule_analyzer import analyze_file


# ── Dockerfile Tests ────────────────────────────────────────────────────────

class TestDockerfileAnalysis:

    def test_detects_latest_tag(self):
        content = "FROM python:latest\nWORKDIR /app\nCOPY . ."
        findings = analyze_file("Dockerfile", "Dockerfile", content)
        issues = [f["issue"] for f in findings]
        assert any("latest" in issue.lower() for issue in issues), (
            "Should detect usage of 'latest' tag in Dockerfile"
        )

    def test_detects_missing_user(self):
        content = "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]"
        findings = analyze_file("Dockerfile", "Dockerfile", content)
        issues = [f["issue"] for f in findings]
        assert any("user" in issue.lower() for issue in issues), (
            "Should detect missing non-root USER instruction"
        )

    def test_detects_missing_healthcheck(self):
        content = "FROM python:3.11-slim\nWORKDIR /app\nUSER appuser\nCMD [\"python\", \"app.py\"]"
        findings = analyze_file("Dockerfile", "Dockerfile", content)
        issues = [f["issue"] for f in findings]
        assert any("healthcheck" in issue.lower() for issue in issues), (
            "Should detect missing HEALTHCHECK instruction"
        )

    def test_clean_dockerfile_has_fewer_findings(self):
        content = (
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "USER appuser\n"
            "HEALTHCHECK CMD curl -f http://localhost:8000/ || exit 1\n"
            "CMD [\"python\", \"app.py\"]"
        )
        findings = analyze_file("Dockerfile", "Dockerfile", content)
        high_findings = [f for f in findings if f["severity"] == "High"]
        assert len(high_findings) == 0, (
            "Well-configured Dockerfile should have no high-severity findings"
        )


# ── Kubernetes Tests ────────────────────────────────────────────────────────

class TestKubernetesAnalysis:

    def test_detects_missing_resource_limits(self):
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
"""
        findings = analyze_file("deployment.yaml", "Kubernetes Manifest", content)
        issues = [f["issue"] for f in findings]
        assert any("resource" in issue.lower() for issue in issues), (
            "Should detect missing resource requests/limits"
        )

    def test_detects_missing_probes(self):
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""
        findings = analyze_file("deployment.yaml", "Kubernetes Manifest", content)
        issues = [f["issue"] for f in findings]
        assert any("livenessprobe" in issue.lower() for issue in issues), (
            "Should detect missing livenessProbe"
        )
        assert any("readinessprobe" in issue.lower() for issue in issues), (
            "Should detect missing readinessProbe"
        )

    def test_detects_latest_image_tag(self):
        content = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: myregistry/myapp:latest
          resources:
            limits:
              cpu: "500m"
"""
        findings = analyze_file("deployment.yaml", "Kubernetes Manifest", content)
        issues = [f["issue"] for f in findings]
        assert any("latest" in issue.lower() for issue in issues), (
            "Should detect usage of 'latest' image tag"
        )

    def test_detects_missing_namespace(self):
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  replicas: 2
"""
        findings = analyze_file("deployment.yaml", "Kubernetes Manifest", content)
        issues = [f["issue"] for f in findings]
        assert any("namespace" in issue.lower() for issue in issues), (
            "Should detect missing namespace"
        )


# ── Terraform Tests ─────────────────────────────────────────────────────────

class TestTerraformAnalysis:

    def test_detects_missing_backend(self):
        content = """
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg" {
  name     = "test-rg"
  location = "East US"
}
"""
        findings = analyze_file("main.tf", "Terraform Configuration", content)
        issues = [f["issue"] for f in findings]
        assert any("backend" in issue.lower() for issue in issues), (
            "Should detect missing backend configuration"
        )

    def test_detects_missing_tags(self):
        content = """
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg" {
  name     = "test-rg"
  location = "East US"
}
"""
        findings = analyze_file("main.tf", "Terraform Configuration", content)
        issues = [f["issue"] for f in findings]
        assert any("tags" in issue.lower() for issue in issues), (
            "Should detect missing resource tags"
        )

    def test_detects_hardcoded_password(self):
        content = """
resource "azurerm_mssql_server" "sql" {
  administrator_login_password = "P@ssw0rd!2024"
}
"""
        findings = analyze_file("main.tf", "Terraform Configuration", content)
        issues = [f["issue"] for f in findings]
        assert any("hardcoded" in issue.lower() or "sensitive" in issue.lower() for issue in issues), (
            "Should detect hardcoded sensitive values"
        )


# ── CI/CD Tests ─────────────────────────────────────────────────────────────

class TestCICDAnalysis:

    def test_github_actions_missing_security_scan(self):
        content = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "building"
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "testing"
"""
        findings = analyze_file("ci.yml", "GitHub Actions Workflow", content)
        issues = [f["issue"] for f in findings]
        assert any("security" in issue.lower() for issue in issues), (
            "Should detect missing security scanning step"
        )

    def test_gitlab_missing_manual_approval(self):
        content = """
stages:
  - build
  - test
  - deploy

build_job:
  stage: build
  script: echo "build"

test_job:
  stage: test
  script: echo "test"

deploy_job:
  stage: deploy
  script: echo "deploy"
"""
        findings = analyze_file("gitlab-ci.yml", "GitLab CI/CD Pipeline", content)
        issues = [f["issue"] for f in findings]
        assert any("manual" in issue.lower() or "approval" in issue.lower() for issue in issues), (
            "Should detect missing manual approval gate"
        )

    def test_github_actions_detects_hardcoded_secrets(self):
        content = """
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "deploying"
        env:
          API_KEY: "sk-abc123secretvalue"
          DB_PASSWORD: "MySecret@Pass"
"""
        findings = analyze_file("deploy.yml", "GitHub Actions Workflow", content)
        issues = [f["issue"] for f in findings]
        assert any("secret" in issue.lower() or "hardcoded" in issue.lower() for issue in issues), (
            "Should detect hardcoded secrets"
        )
