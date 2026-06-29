"""AI-powered root cause analysis with OpenAI fallback to rule-based summaries.

Works in two modes:
  A. If OPENAI_API_KEY is set: sends findings to OpenAI for a professional RCA.
  B. If no API key: generates a structured rule-based summary using Python logic.
"""

import os
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = (
    "You are a Senior Kubernetes and DevOps Architect. Analyze the following "
    "Kubernetes log findings and event findings. Generate a professional "
    "root-cause analysis report. Include issue summary, probable root cause, "
    "immediate fix, long-term fix, kubectl troubleshooting commands, risk level, "
    "business impact, and preventive actions. Keep the explanation practical for "
    "Kubernetes, AKS, Docker, Helm, CI/CD, and enterprise production environments."
)


def generate_root_cause_analysis(findings: list[dict], commands: list[dict]) -> str:
    """Generate a root cause analysis summary.

    Attempts OpenAI API first; falls back to rule-based summary if unavailable.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()

    if api_key and api_key != "your_openai_api_key_here":
        return _ai_analysis(findings, commands, api_key)

    return _rule_based_analysis(findings, commands)


def _ai_analysis(findings: list[dict], commands: list[dict], api_key: str) -> str:
    """Send findings to OpenAI and return the AI-generated analysis."""
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        user_content = _build_prompt_content(findings, commands)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=0.3,
            max_tokens=3000,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        print(f"[WARNING] OpenAI API call failed: {e}")
        print("[INFO] Falling back to rule-based analysis...")
        return _rule_based_analysis(findings, commands)


def _build_prompt_content(findings: list[dict], commands: list[dict]) -> str:
    """Build the prompt content from findings and commands."""
    lines = ["## Kubernetes Log Analysis Findings\n"]

    for i, f in enumerate(findings, 1):
        lines.append(f"### Finding {i}: {f['issue_type']}")
        lines.append(f"- **File:** {f['file_name']}")
        lines.append(f"- **Severity:** {f['severity']}")
        lines.append(f"- **Matched Keyword:** {f['matched_keyword']}")
        lines.append(f"- **Explanation:** {f['explanation']}")
        lines.append(f"- **Probable Causes:** {', '.join(f['probable_causes'])}")
        lines.append("")

    if commands:
        lines.append("## Recommended kubectl Commands\n")
        for cmd in commands:
            lines.append(f"- [{cmd['issue_type']}] `{cmd['command']}` — {cmd['purpose']}")
        lines.append("")

    return "\n".join(lines)


def _rule_based_analysis(findings: list[dict], commands: list[dict]) -> str:
    """Generate a structured rule-based root cause analysis without AI."""
    if not findings:
        return (
            "No Kubernetes issues were detected in the analyzed log files. "
            "All scanned files appear healthy. Continue monitoring with "
            "standard observability practices."
        )

    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    issue_types = list({f["issue_type"] for f in findings})
    critical_count = severity_counts.get("Critical", 0)
    high_count = severity_counts.get("High", 0)

    lines = [
        "## AI Root Cause Analysis (Rule-Based Mode)\n",
        "> Note: Running in rule-based mode. Set OPENAI_API_KEY for AI-powered analysis.\n",
        "### Issue Summary\n",
        f"The analysis detected **{len(findings)} issues** across the scanned files.",
        f"- **Critical:** {critical_count}",
        f"- **High:** {high_count}",
        f"- **Medium:** {severity_counts.get('Medium', 0)}",
        f"- **Low:** {severity_counts.get('Low', 0)}",
        f"\nIssue types found: {', '.join(issue_types)}\n",
    ]

    lines.append("### Probable Root Causes\n")
    for f in findings:
        lines.append(f"**{f['issue_type']}** (Severity: {f['severity']})")
        lines.append(f"- File: `{f['file_name']}`")
        lines.append(f"- Matched: `{f['matched_keyword']}`")
        lines.append(f"- {f['explanation']}")
        lines.append("- Probable causes:")
        for cause in f["probable_causes"][:3]:
            lines.append(f"  - {cause}")
        lines.append("")

    lines.append("### Immediate Fixes\n")
    for f in findings:
        lines.append(f"- **{f['issue_type']}:** {f['recommendation']}")
    lines.append("")

    lines.append("### Long-Term Preventive Actions\n")
    lines.append("- Implement resource requests and limits for all containers")
    lines.append("- Set up Prometheus + Grafana monitoring for cluster health")
    lines.append("- Configure PodDisruptionBudgets for critical workloads")
    lines.append("- Enable cluster autoscaler for dynamic node scaling")
    lines.append("- Implement proper CI/CD pipeline with image scanning")
    lines.append("- Use Helm charts with standardized probe configurations")
    lines.append("- Set up alerting for pod restart counts and OOMKill events")
    lines.append("")

    lines.append("### Risk Assessment\n")
    if critical_count > 0:
        lines.append(
            "**CRITICAL RISK** — Production workloads are impacted. "
            "Immediate investigation and remediation required."
        )
    elif high_count > 0:
        lines.append(
            "**HIGH RISK** — Service degradation likely. "
            "Address high-severity issues within the next maintenance window."
        )
    else:
        lines.append(
            "**MODERATE RISK** — Issues detected but no immediate production impact. "
            "Schedule fixes in the next sprint."
        )

    lines.append("\n### Business Impact\n")
    lines.append("- Application downtime or degraded performance")
    lines.append("- Failed deployments blocking feature releases")
    lines.append("- Customer-facing service disruptions")
    lines.append("- Increased on-call incident response burden")
    lines.append("- Potential SLA violations")

    return "\n".join(lines)
