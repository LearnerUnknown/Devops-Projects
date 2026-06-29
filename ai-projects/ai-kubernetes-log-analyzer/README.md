# AI Kubernetes Log Analyzer

An AI-powered Kubernetes troubleshooting tool that analyzes pod logs, events, and error messages to generate professional root-cause analysis reports with actionable fixes, kubectl commands, and DevOps recommendations.

## Overview

Kubernetes production environments generate massive volumes of logs and events. When pods fail, engineers spend valuable time manually scanning logs, correlating events, and diagnosing root causes. This tool automates that process by:

- Scanning Kubernetes log and event files for known failure patterns
- Classifying issues by type and severity
- Generating targeted kubectl troubleshooting commands
- Producing a professional Markdown report with root-cause analysis
- Optionally using OpenAI for AI-powered analysis summaries

## Problem Statement

DevOps and SRE teams face recurring challenges in Kubernetes environments:

- **CrashLoopBackOff** pods consuming cluster resources without serving traffic
- **OOMKilled** containers causing data loss and service interruptions
- **ImagePullBackOff** blocking deployments due to registry or credential issues
- **Probe failures** causing traffic blackholes and cascading failures
- **Scheduling failures** leaving workloads stuck in Pending state
- **Node pressure** triggering unexpected pod evictions

Manually diagnosing these issues is time-consuming and error-prone, especially during incidents.

## Why This Project

This project demonstrates practical DevOps engineering skills applicable to real production environments:

- **Kubernetes production troubleshooting** — pattern recognition for the most common K8s failures
- **AKS issue debugging** — includes Azure-specific recommendations (ACR, Azure Monitor, AKS diagnostics)
- **Pod failure analysis** — automated detection of 8 critical issue categories
- **Deployment reliability** — actionable recommendations to prevent recurring failures
- **DevOps incident response** — structured reports that accelerate MTTR
- **AI-generated root-cause analysis** — dual-mode architecture (OpenAI + rule-based fallback)
- **CI/CD quality improvement** — GitHub Actions integration for automated analysis

## Tools and Technologies Used

| Category | Tools |
|----------|-------|
| Language | Python 3.11+ |
| AI | OpenAI API (GPT-4o-mini), Rule-based fallback engine |
| Container Orchestration | Kubernetes, AKS, Docker |
| CI/CD | GitHub Actions |
| Package Registry | Azure Container Registry (ACR) |
| Infrastructure as Code | Terraform, Helm Charts |
| Configuration Management | Ansible |
| Security Scanning | Black Duck, Fortify |
| Monitoring | Prometheus, Grafana, Azure Monitor |
| Testing | pytest |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Entry Point (main.py)                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌────────────────────┐                │
│  │  Log Loader   │───▶│  K8s Rule Analyzer  │                │
│  │ (log_loader)  │    │ (8 issue patterns)  │                │
│  └──────────────┘    └─────────┬──────────┘                │
│                                │                            │
│                    ┌───────────▼───────────┐                │
│                    │  Command Recommender   │                │
│                    │  (kubectl commands)    │                │
│                    └───────────┬───────────┘                │
│                                │                            │
│                    ┌───────────▼───────────┐                │
│                    │  AI Root Cause         │                │
│                    │  Analyzer              │                │
│                    │  (OpenAI / Rule-based) │                │
│                    └───────────┬───────────┘                │
│                                │                            │
│                    ┌───────────▼───────────┐                │
│                    │  Report Generator      │                │
│                    │  (Markdown output)     │                │
│                    └───────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **8 Kubernetes Issue Detectors:** CrashLoopBackOff, ImagePullBackOff, OOMKilled, Readiness Probe, Liveness Probe, Pending Pod, Node Pressure, DNS Failure
- **Severity Classification:** Critical, High, Medium, Low
- **kubectl Command Generation:** Tailored troubleshooting commands for each issue type
- **Dual-Mode AI Analysis:** OpenAI-powered or rule-based (works offline without API key)
- **Professional Markdown Reports:** Executive summary, risk scoring, and prioritized action plans
- **CI/CD Integration:** GitHub Actions workflow for automated analysis on every push
- **AKS-Specific Recommendations:** Azure Container Registry, Azure Monitor, AKS diagnostics

## Folder Structure

```
ai-kubernetes-log-analyzer/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
│
├── app/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point
│   ├── log_loader.py              # Load log and event files
│   ├── k8s_rule_analyzer.py       # Rule-based issue detection
│   ├── ai_root_cause_analyzer.py  # AI + fallback analysis
│   ├── command_recommender.py     # kubectl command generation
│   └── report_generator.py        # Markdown report output
│
├── sample-logs/                   # Realistic K8s log samples
│   ├── crashloopbackoff.log
│   ├── imagepullbackoff.log
│   ├── oomkilled.log
│   ├── readiness_probe_failed.log
│   ├── liveness_probe_failed.log
│   ├── pending_pod.log
│   ├── node_pressure.log
│   └── dns_failure.log
│
├── sample-k8s-events/             # K8s event output samples
│   ├── crashloopbackoff-events.txt
│   ├── imagepullbackoff-events.txt
│   ├── oomkilled-events.txt
│   └── pending-pod-events.txt
│
├── reports/                       # Generated analysis reports
│
├── tests/
│   └── test_k8s_rule_analyzer.py
│
└── .github/
    └── workflows/
        └── k8s-log-analysis.yml
```

## How It Works

1. **Load Files** — Recursively scans `--logs` and `--events` directories for `.log`, `.txt`, and `.out` files
2. **Analyze** — Matches file content against 8 Kubernetes issue rule patterns using regex
3. **Classify** — Assigns severity (Critical/High/Medium/Low) and identifies probable causes
4. **Recommend** — Generates targeted kubectl commands for each detected issue type
5. **AI Analysis** — Sends findings to OpenAI for intelligent RCA, or uses rule-based fallback
6. **Report** — Produces a comprehensive Markdown report with executive summary and prioritized action plans

## Supported Kubernetes Issues

| Issue | Severity | Key Indicators |
|-------|----------|----------------|
| CrashLoopBackOff | Critical | Container restart loops, exit code errors, missing env vars |
| ImagePullBackOff | Critical | Registry auth failures, wrong image tags, ACR issues |
| OOMKilled | Critical | Exit code 137, memory limit exceeded, memory leaks |
| Readiness Probe Failed | High | HTTP probe failures, connection refused, timeout |
| Liveness Probe Failed | High | Health endpoint errors, container restarts, deadlocks |
| Pending Pod | High | FailedScheduling, insufficient resources, taint mismatch |
| Node Pressure | High | MemoryPressure, DiskPressure, pod evictions |
| DNS Failure | Medium | Name resolution failures, CoreDNS issues |

## How to Run Locally

### Prerequisites

- Python 3.11+
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/narmadha-devops/Devops-Projects.git
cd Devops-Projects/ai-projects/ai-kubernetes-log-analyzer

# Install dependencies
pip install -r requirements.txt

# (Optional) Set up OpenAI API key for AI-powered analysis
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Run the Analyzer

```bash
python app/main.py \
  --logs sample-logs \
  --events sample-k8s-events \
  --output reports/kubernetes-root-cause-report.md
```

### Run Tests

```bash
pytest tests/ -v
```

## How to Run Using GitHub Actions

1. Push changes to the `main` branch or create a pull request
2. The workflow automatically:
   - Sets up Python 3.11
   - Installs dependencies
   - Runs unit tests
   - Executes the log analyzer
   - Uploads the report as a workflow artifact
3. Download the report from the Actions tab → Artifacts section

## Sample Report Output

The generated report includes:

- **Executive Summary** — Total files analyzed, issues found, severity breakdown
- **Overall Risk Score** — Calculated score based on severity weights
- **Detailed Findings Table** — File, issue type, severity, matched keyword, probable cause
- **Kubectl Commands Table** — Targeted troubleshooting commands with purpose
- **AI Root Cause Analysis** — Intelligent or rule-based summary
- **Immediate Fixes** — Priority actions for each issue type
- **Long-Term Preventive Actions** — Resource management, monitoring, autoscaling
- **AKS Recommendations** — Azure-specific guidance
- **CI/CD Suggestions** — Pipeline improvements
- **Business Impact** — Risk assessment for stakeholders
- **Final Action Plan** — Prioritized checklist (24hrs / 1 week / next sprint)

## Kubectl Commands Generated

Example commands generated for CrashLoopBackOff:

```bash
kubectl get pods -n <namespace>
kubectl describe pod <pod-name> -n <namespace>
kubectl logs <pod-name> -n <namespace> --previous
kubectl get events -n <namespace> --sort-by=.lastTimestamp
kubectl describe deployment <deployment-name> -n <namespace>
```

## AI Integration

The tool supports two analysis modes:

### Mode A: OpenAI-Powered (with API key)
- Set `OPENAI_API_KEY` in `.env` file
- Uses GPT-4o-mini for intelligent root-cause summaries
- Generates context-aware recommendations

### Mode B: Rule-Based (without API key)
- Works completely offline
- Uses Python logic to generate structured analysis
- Includes severity assessment, probable causes, and action plans
- No external dependencies required

## AKS Relevance

This tool is built with Azure Kubernetes Service (AKS) in mind:

- **ACR Integration** — Detects image pull issues related to Azure Container Registry
- **AKS Diagnostics** — Recommendations for enabling Container Insights
- **Azure Monitor** — Guidance on setting up alerts for pod failures
- **Azure Policy** — Suggestions for enforcing resource limits
- **Node Auto-Repair** — Recommendations for AKS node health management
- **Key Vault** — Guidance on secrets management integration

## Business Impact

- **Reduces MTTR** — Automated root-cause analysis cuts incident diagnosis time
- **Prevents Outages** — Proactive detection of issues before they escalate
- **Improves Reliability** — Actionable recommendations for hardening deployments
- **Saves Engineering Time** — Eliminates manual log scanning and correlation
- **Supports Compliance** — Structured reports for audit trails and post-mortems

## Future Enhancements

- [ ] Live Kubernetes cluster integration using `kubectl` or Kubernetes Python client
- [ ] Slack/Teams notification integration for critical findings
- [ ] Prometheus metrics export for monitoring dashboards
- [ ] Web-based dashboard with interactive charts (Flask/FastAPI)
- [ ] Support for EKS and GKE-specific recommendations
- [ ] Historical trend analysis across multiple runs
- [ ] Custom rule definitions via YAML configuration
- [ ] Integration with PagerDuty/OpsGenie for incident management

## Author

**Narmadha Devi R**
DevOps Engineer | 6+ Years Experience

*Expertise: Azure DevOps, GitHub Actions, GitLab CI/CD, Jenkins, Docker, Kubernetes, AKS, ACR, Helm Charts, Terraform, Ansible, Azure VMs, Azure VNets, Azure Storage, Black Duck, Fortify, LoadRunner, MS SQL*
