"""
AI Reviewer Module

Provides two review modes:
  1. OpenAI-powered: Uses GPT to generate a professional executive summary
     when OPENAI_API_KEY is set in the environment.
  2. Rule-based fallback: Generates a structured summary using Python logic
     when no API key is available.

The project is fully functional in either mode.
"""

import os
from typing import List, Dict
from collections import Counter

from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = (
    "You are a Senior DevOps Architect. Review the following DevOps analysis "
    "findings and generate a professional DevOps review report. Include "
    "executive summary, security risks, reliability risks, CI/CD improvements, "
    "Docker recommendations, Kubernetes recommendations, Terraform "
    "recommendations, Ansible recommendations, business impact, and final "
    "action plan. Keep the language practical and suitable for Azure, GitHub "
    "Actions, GitLab CI/CD, Docker, Kubernetes, Terraform, Ansible, Helm, "
    "and enterprise DevOps environments."
)


def generate_ai_summary(findings: List[Dict[str, str]]) -> str:
    """
    Generate a professional review summary.

    Attempts OpenAI first; falls back to rule-based summary if the key
    is missing or the API call fails.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()

    if api_key and api_key != "your-api-key-here":
        try:
            return _openai_summary(findings, api_key)
        except Exception as e:
            print(f"[AI Reviewer] OpenAI call failed ({e}), using rule-based summary.")

    return _rule_based_summary(findings)


def _openai_summary(findings: List[Dict[str, str]], api_key: str) -> str:
    """Call OpenAI to generate the review summary."""
    from openai import OpenAI

    client = OpenAI(api_key=api_key)

    findings_text = _format_findings_for_prompt(findings)

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": findings_text},
        ],
        temperature=0.4,
        max_tokens=2000,
    )

    return response.choices[0].message.content


def _rule_based_summary(findings: List[Dict[str, str]]) -> str:
    """Generate a structured summary without an AI API call."""
    if not findings:
        return (
            "No issues were detected in the scanned DevOps files. "
            "The configurations follow best practices."
        )

    total = len(findings)
    severity_counts = Counter(f["severity"] for f in findings)
    category_counts = Counter(f["category"] for f in findings)
    type_counts = Counter(f["file_type"] for f in findings)

    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)

    lines = []

    # ── Executive Summary ───────────────────────────────────────────────
    lines.append("### Review Summary")
    lines.append("")
    lines.append(
        f"The analysis identified **{total} findings** across "
        f"**{len(type_counts)} file type(s)**: "
        f"**{high} High**, **{medium} Medium**, and **{low} Low** severity."
    )
    lines.append("")

    if high > 0:
        lines.append(
            "**Critical attention required.** High-severity issues include "
            "potential security vulnerabilities, missing reliability safeguards, "
            "and CI/CD pipeline gaps that could impact production stability."
        )
    elif medium > 0:
        lines.append(
            "**Moderate improvements recommended.** The configurations are "
            "functional but would benefit from hardening around security "
            "and reliability best practices."
        )
    else:
        lines.append(
            "**Minor refinements suggested.** Configurations are generally "
            "solid with only cosmetic or low-impact improvements available."
        )
    lines.append("")

    # ── Category Breakdown ──────────────────────────────────────────────
    lines.append("### Risk Breakdown by Category")
    lines.append("")
    for cat, count in category_counts.most_common():
        cat_high = sum(1 for f in findings if f["category"] == cat and f["severity"] == "High")
        lines.append(f"- **{cat}**: {count} issue(s) ({cat_high} high-severity)")
    lines.append("")

    # ── Per-Type Summary ────────────────────────────────────────────────
    lines.append("### Findings by Technology")
    lines.append("")
    for ftype, count in type_counts.most_common():
        lines.append(f"- **{ftype}**: {count} finding(s)")
    lines.append("")

    # ── Prioritized Action Plan ─────────────────────────────────────────
    lines.append("### Prioritized Action Plan")
    lines.append("")
    lines.append("1. **Immediate (High Severity):** Address all security vulnerabilities, "
                 "add missing health probes, configure resource limits, and integrate "
                 "security scanning into CI/CD pipelines.")
    lines.append("2. **Short-Term (Medium Severity):** Pin image and provider versions, "
                 "add deployment approval gates, define namespaces, and implement "
                 "proper tagging strategies.")
    lines.append("3. **Ongoing (Low Severity):** Improve artifact management, refine "
                 "naming conventions, separate environment-specific configurations, "
                 "and add Ansible handlers.")
    lines.append("")

    # ── Business Impact ─────────────────────────────────────────────────
    lines.append("### Business Impact Assessment")
    lines.append("")
    if high >= 3:
        lines.append(
            "The current state poses **significant operational risk**. "
            "Unaddressed high-severity findings could lead to security breaches, "
            "production outages, and compliance failures. Immediate remediation "
            "is strongly recommended before the next production release."
        )
    elif high >= 1:
        lines.append(
            "There is **moderate operational risk**. High-severity items should "
            "be addressed within the current sprint to reduce exposure to "
            "security incidents and reliability degradation."
        )
    else:
        lines.append(
            "Operational risk is **low**. The infrastructure and pipelines are "
            "in reasonable shape. Addressing the remaining findings will further "
            "improve resilience and maintainability."
        )
    lines.append("")

    return "\n".join(lines)


def _format_findings_for_prompt(findings: List[Dict[str, str]]) -> str:
    """Serialize findings into a readable prompt for the AI model."""
    lines = ["DevOps Analysis Findings:", ""]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"{i}. [{f['severity']}] {f['file_type']} — {f['file_name']}: "
            f"{f['issue']} (Category: {f['category']})"
        )
    return "\n".join(lines)
