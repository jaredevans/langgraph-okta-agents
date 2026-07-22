import argparse
import logging
import sys

from okta_agents.config import load_settings
from okta_agents.runner import make_llm, make_retriever, run_pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="okta_agents",
                                     description="Multi-agent Okta log triage")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run the triage pipeline")
    run.add_argument("--log", required=True, help="Path to Okta system log CSV")
    run.add_argument("--max-cases", type=int, default=None)
    run.add_argument("--risk-threshold", type=int, default=None)
    run.add_argument("--limit-rows", type=int, default=None,
                     help="Only read the first N CSV rows (smoke testing)")
    run.add_argument("--output", default=None, help="Reports directory")
    run.add_argument("--rebuild-kb", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    settings = load_settings()
    if args.output:
        from pathlib import Path

        settings.reports_dir = Path(args.output)

    tickets = run_pipeline(
        settings,
        args.log,
        llm=make_llm(settings),
        retriever=make_retriever(settings, rebuild=args.rebuild_kb),
        limit_rows=args.limit_rows,
        max_cases=args.max_cases,
        risk_threshold=args.risk_threshold,
    )
    escalated = sum(t.status == "escalated" for t in tickets)
    errors = sum(t.status == "error" for t in tickets)
    print(f"\n{len(tickets)} case(s): {escalated} escalated, "
          f"{len(tickets) - escalated - errors} dismissed, {errors} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
