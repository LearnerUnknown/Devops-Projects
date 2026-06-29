"""Generate a professional Markdown root-cause analysis report."""

import os
from datetime import datetime


def generate_report(
    files: list[dict],
    findings: list[dict],
    commands: list[dict],
    ai_summary: str,
    output_path: str,
) -> str:
    """Build and write the full Markdown report.

    Returns:
        The absolute path of the written report file.
    """
    total_files = len(files)
    total_findings = len(findings)
    severity_counts = _count_severities(findings)
    risk_score = _calculate_risk_score(severity_counts)

    sections = [
        _header(),
        _executive_summary(total_files, total_findings, severity_counts, risk_score),
        _overall_risk_score(risk_score, severity_counts),
        _files_analyzed(files),
        _issues_detected(findings),
        _detailed_findings_table(findings),
        _kubectl_commands_table(commands),
        _ai_root_cause_section(ai_summary),
        _immediate_fixes(findings),
        _long_term_actions(),
        _aks_recommendations(),
        _cicd_suggestions(),
        _business_impact(severity_counts),
        _key_highlights(total_findings),
        _final_action_plan(findings),
        _footer(),
    ]

    report = "\n\n".join(sections)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    return os.path.abspath(output_path)


def _header() -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        "# AI Kubernetes Log Analysis Report\n\n"
        f"**Generated:** {timestamp}  \n"
        "**Tool:** AI Kubernetes Log Analyzer  \n"
        "**Author:** Narmadha Devi R"
    )


def _executive_summary(
    total_files: int,
    total_findings: int,
    severity_counts: dict,
    risk_score: str,
) -> str:
    return (
        "## Executive Summary\n\n"
        f"This report analyzes **{total_files} Kubernetes log/event files** and "
        f"detected **{total_findings} issues**.\n\n"
        f"- **Critical Issues:** {severity_counts.get('Critical', 0)}\n"
        f"- **High Issues:** {severity_counts.get('High', 0)}\n"
        f"- **Medium Issues:** {severity_counts.get('Medium', 0)}\n"
        f"- **Low Issues:** {severity_counts.get('Low', 0)}\n\n"
        f"**Overall Risk Score:** {risk_score}"
    )


def _overall_risk_score(risk_score: str, severity_counts: dict) -> str:
    if severity_counts.get("Critical", 0) > 0:
        detail = "Immediate action required. Production workloads are at risk."
    elif severity_counts.get("High", 0) > 0:
        detail = "High-priority issues detected. Address within the next maintenance window."
    elif severity_counts.get("Medium", 0) > 0:
        detail = "Moderate issues found. Schedule fixes in the upcoming sprint."
    else:
        detail = "No significant issues detected. Continue standard monitoring."

    return f"## Overall Risk Score\n\n**{risk_score}**\n\n{detail}"


def _files_analyzed(files: list[dict]) -> str:
    lines = ["## Files Analyzed\n", "| # | File Name | Type | Path |", "|---|-----------|------|------|"]
    for i, f in enumerate(files, 1):
        lines.append(f"| {i} | {f['file_name']} | {f['file_type']} | `{f['file_path']}` |")
    return "\n".join(lines)


def _issues_detected(findings: list[dict]) -> str:
    if not findings:
        return "## Issues Detected\n\nNo issues detected."

    issue_types = {}
    for f in findings:
        key = f["issue_type"]
        if key not in issue_types:
            issue_types[key] = {"severity": f["severity"], "count": 0}
        issue_types[key]["count"] += 1

    lines = ["## Issues Detected\n", "| Issue Type | Severity | Occurrences |", "|------------|----------|-------------|"]
    for issue, info in issue_types.items():
        lines.append(f"| {issue} | {info['severity']} | {info['count']} |")
    return "\n".join(lines)


def _detailed_findings_table(findings: list[dict]) -> str:
    if not findings:
        return "## Detailed Root Cause Findings\n\nNo findings to report."

    lines = [
        "## Detailed Root Cause Findings\n",
        "| File | Issue Type | Severity | Matched Keyword | Probable Cause | Recommendation |",
        "|------|------------|----------|-----------------|----------------|----------------|",
    ]
    for f in findings:
        top_cause = f["probable_causes"][0] if f["probable_causes"] else "N/A"
        lines.append(
            f"| {f['file_name']} | {f['issue_type']} | {f['severity']} "
            f"| `{f['matched_keyword']}` | {top_cause} | {f['recommendation'][:80]}... |"
        )
    return "\n".join(lines)


def _kubectl_commands_table(commands: list[dict]) -> str:
    if not commands:
        return "## Kubectl Troubleshooting Commands\n\nNo commands to recommend."

    lines = [
        "## Kubectl Troubleshooting Commands\n",
        "| Issue Type | Command | Purpose |",
        "|------------|---------|---------|",
    ]
    for cmd in commands:
        lines.append(
            f"| {cmd['issue_type']} | `{cmd['command']}` | {cmd['purpose']} |"
        )
    return "\n".join(lines)


def _ai_root_cause_section(ai_summary: str) -> str:
    return f"## AI Root Cause Analysis\n\n{ai_summary}"


def _immediate_fixes(findings: list[dict]) -> str:
    if not findings:
        return "## Immediate Fixes\n\nNo immediate fixes required."

    seen = set()
    lines = ["## Immediate Fixes\n"]
    for f in findings:
        if f["issue_type"] not in seen:
            seen.add(f["issue_type"])
            lines.append(f"### {f['issue_type']}\n")
            lines.append(f"- {f['recommendation']}")
            lines.append(f"- Primary suspect: {f['probable_causes'][0]}")
            lines.append("")
    return "\n".join(lines)


def _long_term_actions() -> str:
    return (
        "## Long-Term Preventive Actions\n\n"
        "1. **Resource Management:** Define CPU and memory requests/limits for all containers\n"
        "2. **Monitoring:** Implement Prometheus + Grafana dashboards for cluster health\n"
        "3. **Alerting:** Configure alerts for pod restarts, OOMKills, and node pressure\n"
        "4. **Autoscaling:** Enable Horizontal Pod Autoscaler (HPA) and Cluster Autoscaler\n"
        "5. **Image Management:** Use immutable image tags and scan images in CI/CD\n"
        "6. **Helm Charts:** Standardize probe configs, resource limits, and security contexts\n"
        "7. **PodDisruptionBudgets:** Set PDBs for critical workloads to ensure availability\n"
        "8. **GitOps:** Use ArgoCD or Flux for declarative deployments and drift detection"
    )


def _aks_recommendations() -> str:
    return (
        "## AKS-Specific Recommendations\n\n"
        "- Enable **AKS Diagnostics** and **Container Insights** for centralized logging\n"
        "- Use **Azure Monitor** alerts for node conditions and pod failures\n"
        "- Configure **ACR integration** with AKS for seamless image pulling\n"
        "- Enable **Azure Policy for AKS** to enforce resource limits and security baselines\n"
        "- Use **AKS node auto-repair** to automatically fix unhealthy nodes\n"
        "- Implement **Azure Key Vault** integration for secrets management\n"
        "- Use **AKS cluster autoscaler** with appropriate min/max node counts\n"
        "- Enable **Azure Defender for Kubernetes** for threat detection"
    )


def _cicd_suggestions() -> str:
    return (
        "## CI/CD Improvement Suggestions\n\n"
        "- Add **container image scanning** (Trivy, Snyk) to the pipeline\n"
        "- Run **Kubernetes manifest validation** (kubeval, kubeconform) before deployment\n"
        "- Implement **canary deployments** or **blue-green deployments** for safe rollouts\n"
        "- Add **integration tests** that validate health endpoints post-deployment\n"
        "- Use **Helm lint** and **dry-run** in CI before applying changes\n"
        "- Implement **automated rollback** on deployment failure\n"
        "- Add **resource limit validation** as a CI gate\n"
        "- Use **Black Duck / Fortify** scans for security compliance"
    )


def _business_impact(severity_counts: dict) -> str:
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)

    lines = [
        "## Business Impact\n",
        f"- **{critical} Critical** and **{high} High** severity issues detected",
        "- Potential for application downtime and customer-facing disruptions",
        "- Failed deployments may block feature releases and sprint deliverables",
        "- Increased operational burden on the DevOps/SRE team",
        "- Risk of SLA violations if issues persist in production",
        "- Infrastructure costs may increase due to inefficient resource utilization",
    ]
    return "\n".join(lines)


def _key_highlights(total_findings: int) -> str:
    return (
        "## Key Highlights\n\n"
        f"1. **Coverage:** Analyzed multiple K8s log sources, detected {total_findings} issues across 8 categories\n"
        "2. **Rule Engine:** Pattern-matching engine covering CrashLoopBackOff, OOMKilled, "
        "ImagePullBackOff, probe failures, scheduling issues, node pressure, and DNS failures\n"
        "3. **AI Integration:** Dual-mode architecture — OpenAI for smart analysis, rule-based fallback for offline use\n"
        "4. **Actionable Output:** Auto-generates kubectl commands tailored to each issue type\n"
        "5. **CI/CD Ready:** GitHub Actions workflow runs analysis on every push and uploads the report as an artifact\n"
        "6. **Production Relevance:** Covers real-world AKS/EKS/GKE troubleshooting scenarios\n"
        "7. **DevOps Best Practices:** Includes preventive actions, monitoring recommendations, and Helm/Terraform suggestions\n"
        "8. **Modular Design:** Clean Python architecture with pytest unit tests and proper error handling"
    )


def _final_action_plan(findings: list[dict]) -> str:
    if not findings:
        return "## Final Action Plan\n\nNo issues detected. Continue standard monitoring."

    lines = [
        "## Final Action Plan\n",
        "### Priority 1 — Immediate (Next 24 Hours)",
    ]

    critical = [f for f in findings if f["severity"] == "Critical"]
    if critical:
        for f in critical:
            lines.append(f"- [ ] Fix **{f['issue_type']}** in `{f['file_name']}`")
    else:
        lines.append("- No critical items")

    lines.append("\n### Priority 2 — Short-Term (Next 1 Week)")
    high = [f for f in findings if f["severity"] == "High"]
    if high:
        for f in high:
            lines.append(f"- [ ] Address **{f['issue_type']}** in `{f['file_name']}`")
    else:
        lines.append("- No high-priority items")

    lines.append("\n### Priority 3 — Long-Term (Next Sprint)")
    lines.append("- [ ] Review and set resource requests/limits for all deployments")
    lines.append("- [ ] Implement monitoring and alerting dashboards")
    lines.append("- [ ] Standardize Helm chart probe configurations")
    lines.append("- [ ] Enable cluster autoscaler and HPA")
    lines.append("- [ ] Conduct a Kubernetes security audit")

    return "\n".join(lines)


def _footer() -> str:
    return (
        "---\n\n"
        "*Report generated by AI Kubernetes Log Analyzer*  \n"
        "*Author: Narmadha Devi R | DevOps Engineer*"
    )


def _count_severities(findings: list[dict]) -> dict:
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def _calculate_risk_score(severity_counts: dict) -> str:
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)

    score = critical * 40 + high * 25 + medium * 10
    if score >= 100:
        return "CRITICAL (Score: {}/100+)".format(min(score, 200))
    elif score >= 60:
        return f"HIGH (Score: {score}/100)"
    elif score >= 25:
        return f"MEDIUM (Score: {score}/100)"
    else:
        return f"LOW (Score: {score}/100)"
