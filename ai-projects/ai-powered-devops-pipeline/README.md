# DevOps Pipeline Reviewer

A Python CLI tool that scans DevOps configuration files and generates a Markdown report with security, reliability, and best-practice recommendations.

Supports GitHub Actions, GitLab CI/CD, Dockerfile, Terraform, Kubernetes, Helm, and Ansible files.

## Features

- Recursive file discovery and classification
- Rule-based checks for security, CI/CD, and infrastructure
- Optional OpenAI summary (falls back to rule-based output without an API key)
- Markdown report with risk score, findings table, and action plan
- GitHub Actions workflow for automated reviews

## Project Structure

```
ai-powered-devops-pipeline/
├── app/
│   ├── main.py
│   ├── file_loader.py
│   ├── rule_analyzer.py
│   ├── ai_reviewer.py
│   └── report_generator.py
├── sample-devops-files/
├── tests/
├── reports/
└── requirements.txt
```

## Requirements

- Python 3.9+
- pip

## Setup

```bash
cd ai-projects/ai-powered-devops-pipeline
pip install -r requirements.txt

# Optional: enable OpenAI summaries
cp .env.example .env
# Add OPENAI_API_KEY to .env
```

## Usage

```bash
python app/main.py --path sample-devops-files --output reports/devops-review-report.md
```

## Tests

```bash
pytest tests/ -v
```

## Checks Covered

**CI/CD:** build/test stages, security scanning, deploy stages, approval gates, artifacts, hardcoded secrets

**Docker:** image pinning, non-root user, HEALTHCHECK, minimal packages

**Kubernetes:** resource limits, probes, replicas, image tags, namespace

**Terraform:** remote backend, provider pinning, variables, tags, sensitive values

**Helm:** image config, resources, service type, environment values

**Ansible:** variables, privilege escalation, secrets, handlers, task names
