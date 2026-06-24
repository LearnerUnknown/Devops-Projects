"""
Report Generator

Produces a Markdown report from analysis findings and review summary.
"""

from typing import List, Dict
from collections import Counter
from datetime import datetime


def generate_report(
    findings: List[Dict[str, str]],
    ai_summary: str,
    files_analyzed: List[Dict[str, str]],
) -> str:
    """Build the full Markdown report and return it as a string."""
    sections = [
        _header(),
        _executive_summary(findings, ai_summary),
        _overall_risk_score(findings),
        _files_analyzed_section(files_analyzed),
        _key_findings_summary(findings),
        _detailed_findings_table(findings),
        _category_section(findings, "Security", "Security Recommendations"),
        _category_section(findings, "Reliability", "Reliability Recommendations"),
        _category_section(findings, "CI/CD", "CI/CD Recommendations"),
        _type_section(findings, "Dockerfile", "Docker Recommendations"),
        _type_section(findings, "Kubernetes Manifest", "Kubernetes Recommendations"),
        _type_section(findings, "Terraform Configuration", "Terraform Recommendations"),
        _type_section(findings, "Helm Values", "Helm Recommendations"),
        _type_section(findings, "Ansible Playbook", "Ansible Recommendations"),
        _business_impact(findings),
        _final_action_plan(findings),
        _footer(),
    ]

    return "\n\n".join(sections)


# ── Sections ────────────────────────────────────────────────────────────────

def _header() -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        "# DevOps Pipeline Review Report\n\n"
        f"> Generated on **{timestamp}**"
    )


def _executive_summary(findings: List[Dict[str, str]], ai_summary: str) -> str:
    lines = ["## Executive Summary", ""]
    total = len(findings)
    severity = Counter(f["severity"] for f in findings)
    lines.append(
        f"This report covers **{total} findings** — "
        f"**{severity.get('High', 0)} High**, "
        f"**{severity.get('Medium', 0)} Medium**, "
        f"**{severity.get('Low', 0)} Low** severity."
    )
    lines.append("")
    lines.append(ai_summary)
    return "\n".join(lines)


def _overall_risk_score(findings: List[Dict[str, str]]) -> str:
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")

    score = high * 10 + medium * 5 + low * 1
    max_possible = len(findings) * 10 if findings else 1
    normalized = min(round((score / max_possible) * 100), 100)

    if normalized >= 70:
        level = "Critical"
        emoji = "🔴"
    elif normalized >= 40:
        level = "Moderate"
        emoji = "🟡"
    else:
        level = "Low"
        emoji = "🟢"

    return (
        f"## Overall Risk Score\n\n"
        f"| Metric | Value |\n"
        f"|--------|-------|\n"
        f"| Risk Score | **{normalized}/100** |\n"
        f"| Risk Level | {emoji} **{level}** |\n"
        f"| High Severity | {high} |\n"
        f"| Medium Severity | {medium} |\n"
        f"| Low Severity | {low} |\n"
        f"| Total Findings | {len(findings)} |"
    )


def _files_analyzed_section(files_analyzed: List[Dict[str, str]]) -> str:
    lines = ["## Files Analyzed", ""]
    lines.append("| # | File | Type |")
    lines.append("|---|------|------|")
    for i, f in enumerate(files_analyzed, 1):
        lines.append(f"| {i} | `{f['file_name']}` | {f['file_type']} |")
    return "\n".join(lines)


def _key_findings_summary(findings: List[Dict[str, str]]) -> str:
    lines = ["## Key Findings Summary", ""]
    category_counts = Counter(f["category"] for f in findings)
    for cat, count in category_counts.most_common():
        high_count = sum(1 for f in findings if f["category"] == cat and f["severity"] == "High")
        lines.append(f"- **{cat}**: {count} finding(s) — {high_count} high severity")
    return "\n".join(lines)


def _detailed_findings_table(findings: List[Dict[str, str]]) -> str:
    lines = ["## Detailed Findings", ""]
    lines.append("| File | Type | Category | Severity | Issue | Recommendation |")
    lines.append("|------|------|----------|----------|-------|----------------|")
    for f in sorted(findings, key=lambda x: {"High": 0, "Medium": 1, "Low": 2}[x["severity"]]):
        sev_badge = {"High": "🔴 High", "Medium": "🟡 Medium", "Low": "🟢 Low"}[f["severity"]]
        lines.append(
            f"| `{f['file_name']}` | {f['file_type']} | {f['category']} "
            f"| {sev_badge} | {f['issue']} | {f['recommendation']} |"
        )
    return "\n".join(lines)


def _category_section(findings: List[Dict[str, str]], category: str, title: str) -> str:
    items = [f for f in findings if f["category"] == category]
    lines = [f"## {title}", ""]
    if not items:
        lines.append(f"No {category.lower()} issues detected. Good job!")
        return "\n".join(lines)
    for f in items:
        lines.append(f"- **[{f['severity']}]** `{f['file_name']}`: {f['issue']}")
        lines.append(f"  - *Recommendation:* {f['recommendation']}")
    return "\n".join(lines)


def _type_section(findings: List[Dict[str, str]], file_type: str, title: str) -> str:
    items = [f for f in findings if f["file_type"] == file_type]
    lines = [f"## {title}", ""]
    if not items:
        lines.append(f"No issues detected for {file_type}. Configuration looks solid.")
        return "\n".join(lines)
    for f in items:
        lines.append(f"- **[{f['severity']}]** {f['issue']}")
        lines.append(f"  - *Recommendation:* {f['recommendation']}")
    return "\n".join(lines)


def _business_impact(findings: List[Dict[str, str]]) -> str:
    high = sum(1 for f in findings if f["severity"] == "High")
    lines = ["## Business Impact", ""]

    lines.append("Addressing the findings in this report will:")
    lines.append("")
    lines.append("- **Reduce security risk** by eliminating hardcoded secrets, "
                 "enforcing image pinning, and integrating automated security scanning.")
    lines.append("- **Improve reliability** by adding health probes, resource limits, "
                 "and high-availability configurations.")
    lines.append("- **Strengthen CI/CD** by ensuring build, test, security scan, and "
                 "deployment stages are properly configured with approval gates.")
    lines.append("- **Support compliance** with enterprise standards for Azure, "
                 "Kubernetes, Terraform, and Ansible environments.")

    if high >= 3:
        lines.append("")
        lines.append(
            "> **Warning:** Multiple high-severity issues detected. "
            "Immediate remediation is recommended before the next production deployment."
        )

    return "\n".join(lines)


def _final_action_plan(findings: List[Dict[str, str]]) -> str:
    high_items = [f for f in findings if f["severity"] == "High"]
    medium_items = [f for f in findings if f["severity"] == "Medium"]
    low_items = [f for f in findings if f["severity"] == "Low"]

    lines = ["## Final Action Plan", ""]

    lines.append("### Immediate Priority (High Severity)")
    if high_items:
        for f in high_items:
            lines.append(f"- [ ] {f['issue']} — `{f['file_name']}`")
    else:
        lines.append("- No high-severity actions required.")

    lines.append("")
    lines.append("### Short-Term Priority (Medium Severity)")
    if medium_items:
        for f in medium_items:
            lines.append(f"- [ ] {f['issue']} — `{f['file_name']}`")
    else:
        lines.append("- No medium-severity actions required.")

    lines.append("")
    lines.append("### Ongoing Improvements (Low Severity)")
    if low_items:
        for f in low_items:
            lines.append(f"- [ ] {f['issue']} — `{f['file_name']}`")
    else:
        lines.append("- No low-severity actions required.")

    return "\n".join(lines)


def _footer() -> str:
    return f"---\n\n*Report generated on {datetime.now().strftime('%Y-%m-%d')}*"
