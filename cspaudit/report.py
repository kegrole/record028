"""Report assembly and JSON file loading."""

import json

from .evaluator import evaluate
from .parser import load_policies


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_report(policies_data, requests_data):
    policies = load_policies(policies_data)
    if isinstance(requests_data, dict):
        requests = requests_data.get("requests", [])
    else:
        requests = requests_data

    report = evaluate(policies, requests)
    enforced = report["enforced"]
    report_only = report["report_only"]
    report["summary"] = {
        "policy_count": len(policies),
        "request_count": len(requests),
        "allowed": sum(1 for item in enforced if item["allowed"]),
        "denied": sum(1 for item in enforced if not item["allowed"]),
        "report_only_allowed": sum(1 for item in report_only if item["allowed"]),
        "report_only_denied": sum(1 for item in report_only if not item["allowed"]),
    }
    return report


def write_report(path, report):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def summary_line(summary):
    return (
        "策略数: {policy_count}, 请求数: {request_count}, "
        "允许数: {allowed}, 拒绝数: {denied}"
    ).format(**summary)
