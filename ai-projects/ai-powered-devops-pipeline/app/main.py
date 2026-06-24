"""
DevOps Pipeline Reviewer — Entry Point

Usage:
    python app/main.py --path sample-devops-files --output reports/devops-review-report.md
"""

import argparse
import os
import sys

from file_loader import load_files
from rule_analyzer import analyze_all
from ai_reviewer import generate_ai_summary
from report_generator import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="DevOps Pipeline Reviewer — analyze configs and generate reports"
    )
    parser.add_argument(
        "--path",
        required=True,
        help="Path to the folder containing DevOps configuration files",
    )
    parser.add_argument(
        "--output",
        default="reports/devops-review-report.md",
        help="Output path for the generated Markdown report",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  DevOps Pipeline Reviewer")
    print("=" * 60)

    # Step 1 — Load files
    print(f"\n[1/4] Scanning directory: {args.path}")
    try:
        files = load_files(args.path)
    except FileNotFoundError as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    if not files:
        print("  No supported DevOps files found. Exiting.")
        sys.exit(0)

    print(f"  Found {len(files)} DevOps file(s):")
    for f in files:
        print(f"    - {f['file_name']} ({f['file_type']})")

    # Step 2 — Run rule-based analysis
    print("\n[2/4] Running rule-based analysis...")
    findings = analyze_all(files)
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")
    print(f"  Detected {len(findings)} finding(s): {high} High, {medium} Medium, {low} Low")

    # Step 3 — Generate AI / rule-based summary
    print("\n[3/4] Generating review summary...")
    ai_summary = generate_ai_summary(findings)
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    mode = "OpenAI" if (api_key and api_key != "your-api-key-here") else "Rule-Based"
    print(f"  Summary mode: {mode}")

    # Step 4 — Generate report
    print("\n[4/4] Generating Markdown report...")
    report = generate_report(findings, ai_summary, files)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"  Report saved to: {args.output}")
    print("\n" + "=" * 60)
    print(f"  Review complete! Open {args.output} to view the report.")
    print("=" * 60)


if __name__ == "__main__":
    main()
