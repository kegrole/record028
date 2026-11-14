"""Command-line entry point for cspaudit."""

import argparse
import os

from .report import build_report, load_json, summary_line, write_report


def build_parser():
    parser = argparse.ArgumentParser(description="Evaluate CSP policies against script requests.")
    parser.add_argument("--policies", required=True, help="Path to policies JSON")
    parser.add_argument("--requests", required=True, help="Path to requests JSON")
    parser.add_argument("--out", required=True, help="Path to output report JSON")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    policies_data = load_json(args.policies)
    requests_data = load_json(args.requests)
    report = build_report(policies_data, requests_data)

    output_dir = os.path.dirname(os.path.abspath(args.out))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    write_report(args.out, report)
    print(summary_line(report["summary"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
