"""CLI entry point for the AI Kubernetes Log Analyzer.

Usage:
    python app/main.py --logs sample-logs --events sample-k8s-events --output reports/kubernetes-root-cause-report.md
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.log_loader import load_logs, load_events
from app.k8s_rule_analyzer import analyze
from app.command_recommender import get_commands
from app.ai_root_cause_analyzer import generate_root_cause_analysis
from app.report_generator import generate_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Kubernetes Log Analyzer — Analyze K8s pod logs and events for root-cause analysis",
    )
    parser.add_argument(
        "--logs",
        required=True,
        help="Folder path containing Kubernetes log files (.log, .txt, .out)",
    )
    parser.add_argument(
        "--events",
        required=False,
        default=None,
        help="Optional folder path containing Kubernetes event output files",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for the generated Markdown report",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("=" * 60)
    print("  AI Kubernetes Log Analyzer")
    print("=" * 60)

    # 1. Load log and event files
    print(f"\n[1/5] Loading log files from: {args.logs}")
    log_files = load_logs(args.logs)
    print(f"      Found {len(log_files)} log file(s)")

    print(f"[2/5] Loading event files from: {args.events or '(not provided)'}")
    event_files = load_events(args.events)
    print(f"      Found {len(event_files)} event file(s)")

    all_files = log_files + event_files
    if not all_files:
        print("\n[ERROR] No files found to analyze. Check your --logs and --events paths.")
        sys.exit(1)

    # 2. Run rule-based analysis
    print("\n[3/5] Running Kubernetes issue analysis...")
    findings = analyze(all_files)
    print(f"      Detected {len(findings)} issue(s)")

    for f in findings:
        print(f"      - [{f['severity']}] {f['issue_type']} in {f['file_name']}")

    # 3. Generate kubectl recommendations
    print("\n[4/5] Generating kubectl command recommendations...")
    commands = get_commands(findings)
    print(f"      Generated {len(commands)} command(s)")

    # 4. AI root cause analysis
    print("\n[5/5] Generating root cause analysis...")
    ai_summary = generate_root_cause_analysis(findings, commands)

    # 5. Generate report
    report_path = generate_report(all_files, findings, commands, ai_summary, args.output)

    print("\n" + "=" * 60)
    print("  Analysis Complete!")
    print("=" * 60)
    print(f"\n  Report saved to: {report_path}")
    print(f"  Total files analyzed: {len(all_files)}")
    print(f"  Total issues found: {len(findings)}")
    print(f"  Kubectl commands: {len(commands)}")
    print()


if __name__ == "__main__":
    main()
