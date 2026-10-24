"""Evaluation runner for GhostGuard.
Displays evaluation metrics and token usage summaries.
"""
from pathlib import Path
import sys

def main():
    eval_dir = Path(__file__).resolve().parent
    report_path = eval_dir / "evaluation_report.md"
    usage_path = eval_dir / "usage_report.md"

    print("=" * 60)
    print("GhostGuard - Deletion Audit Evaluation & Usage Summary")
    print("=" * 60)

    if report_path.exists():
        print(f"\n[Report: {report_path.name}]")
        print(report_path.read_text(encoding="utf-8"))
    else:
        print(f"Evaluation report not found at {report_path}")

    if usage_path.exists():
        print(f"\n[Report: {usage_path.name}]")
        print(usage_path.read_text(encoding="utf-8"))
    else:
        print(f"Usage report not found at {usage_path}")

if __name__ == "__main__":
    main()
