import json
import os
import tempfile
import unittest

from cspaudit.cli import main
from cspaudit.evaluator import evaluate_request
from cspaudit.hashcheck import content_digest, nonce_matches
from cspaudit.parser import parse_header
from cspaudit.report import build_report, load_json


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGINAL_INLINE = "window.cspDemo = 'allowed';"
CHANGED_INLINE = "window.cspDemo = 'blocked';"
CORRECT_NONCE = "correct-nonce-42"
DOCUMENT_ORIGIN = "https://app.example.com"


class CspAuditAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.policies_data = load_json(os.path.join(ROOT, "demo", "policies.json"))
        self.requests_data = load_json(os.path.join(ROOT, "demo", "requests.json"))
        self.report = build_report(self.policies_data, self.requests_data)
        self.policies = {policy.policy_id: policy for policy in parse_policy_collection(self.policies_data)}
        self.requests = {request["id"]: request for request in self.requests_data["requests"]}
        self.enforced = {item["request_id"]: item for item in self.report["enforced"]}

    def test_01_six_required_policies_and_explicit_applicability(self):
        enforced = [policy for policy in self.policies.values() if policy.mode == "enforce"]
        self.assertEqual(
            sorted(policy.policy_id for policy in enforced),
            [
                "p1-cdn",
                "p2-self-only",
                "p3-nonce",
                "p4-sha256",
                "p5-inline-eval",
                "p6-invalid-none",
            ],
        )
        self.assertEqual(self.report["summary"]["policy_count"], 7)
        for request in self.requests.values():
            self.assertTrue(request.get("policy_ids"))

    def test_02_external_cdn_allowed_then_denied_by_self_only(self):
        request = self.requests["r1-cdn-p1"]
        allowed = evaluate_request(self.policies["p1-cdn"], request)
        denied = evaluate_request(self.policies["p2-self-only"], request)
        self.assertTrue(allowed["allowed"])
        self.assertFalse(denied["allowed"])
        self.assertEqual(self.enforced["r1-cdn-p1"]["directive"], "script-src")
        self.assertFalse(self.enforced["r2-cdn-p2"]["allowed"])

    def test_03_inline_nonce_and_unsafe_inline_decisions(self):
        correct = evaluate_request(self.policies["p3-nonce"], self.requests["r3-correct-nonce"])
        wrong = evaluate_request(self.policies["p3-nonce"], self.requests["r4-wrong-nonce"])
        inline_allowed = evaluate_request(self.policies["p5-inline-eval"], self.requests["r5-unsafe-inline"])
        inline_denied = evaluate_request(self.policies["p2-self-only"], self.requests["r6-inline-denied"])

        self.assertTrue(correct["allowed"])
        self.assertFalse(wrong["allowed"])
        self.assertIn("逐字节", wrong["reason"])
        self.assertTrue(inline_allowed["allowed"])
        self.assertFalse(inline_denied["allowed"])
        self.assertTrue(nonce_matches(CORRECT_NONCE, CORRECT_NONCE))
        self.assertFalse(nonce_matches(CORRECT_NONCE, CORRECT_NONCE[:-1]))

    def test_04_sha256_base_value_is_derived_from_utf8_content(self):
        digest = content_digest(ORIGINAL_INLINE, "sha256")
        self.assertEqual(digest, "zX7EsrmGhFUKmpfx7CNjUxC3MwA34cj7M3slNo4T5dk")
        self.assertNotIn("=", digest)
        original = evaluate_request(self.policies["p4-sha256"], self.requests["r7-correct-hash"])
        changed = evaluate_request(self.policies["p4-sha256"], self.requests["r8-changed-hash"])
        self.assertTrue(original["allowed"])
        self.assertFalse(changed["allowed"])
        self.assertIn("哈希", changed["reason"])

    def test_05_none_with_other_sources_denies_everything(self):
        directive = self.policies["p6-invalid-none"].directives["script-src"]
        self.assertTrue(directive.invalid_none)
        result = self.enforced["r10-invalid-none"]
        self.assertFalse(result["allowed"])
        self.assertIn("'none' 与其它来源并存", result["reason"])
        self.assertIn("禁止全部", result["reason"])

    def test_06_report_only_unknown_directives_are_ignored(self):
        policy = self.policies["ro1-typo"]
        self.assertEqual(policy.mode, "report-only")
        self.assertEqual(set(policy.directives), {"script-src"})
        self.assertNotIn("scirpt-src", policy.directives)
        self.assertNotIn("foo-src", policy.directives)
        report_only_ids = [item["request_id"] for item in self.report["report_only"]]
        self.assertEqual(sorted(report_only_ids), sorted(self.requests))
        self.assertEqual(
            self.report["report_only"][0]["reason"].split("]", 1)[0],
            "[report-only:ro1-typo",
        )

    def test_07_multiple_policies_use_intersection(self):
        mixed = self.enforced["r11-intersection"]
        self.assertFalse(mixed["allowed"])
        self.assertIn("交集", mixed["reason"])
        both_allow = self.enforced["r12-multiple-policies-allow"]
        self.assertTrue(both_allow["allowed"])

    def test_08_report_fields_and_unsafe_keyword_locations(self):
        for result in self.report["enforced"] + self.report["report_only"]:
            self.assertEqual(
                set(result),
                {"directive", "request_id", "allowed", "reason"},
            )
        self.assertEqual(
            self.report["unsafe_inline_locations"],
            [{"policy_id": "p5-inline-eval", "directive": "script-src", "mode": "enforce"}],
        )
        self.assertEqual(
            self.report["unsafe_eval_locations"],
            [{"policy_id": "p5-inline-eval", "directive": "script-src", "mode": "enforce"}],
        )

    def test_parser_ignores_unknown_directives_and_normalizes_names(self):
        policy = parse_header(
            "SCRIPT-SRC 'self'; UNKNOWN-SRC https://example.com; default-src 'none'",
            policy_id="x",
        )
        self.assertEqual(set(policy.directives), {"script-src", "default-src"})
        self.assertEqual(policy.directives["script-src"].name, "script-src")

    def test_generic_source_forms_are_evaluated_by_rules(self):
        wildcard = parse_header("script-src *.example.com data: blob:", document_origin=DOCUMENT_ORIGIN)
        self.assertTrue(evaluate_request(wildcard, {
            "id": "wildcard",
            "type": "external",
            "url": "https://assets.example.com/lib.js",
        })["allowed"])
        self.assertTrue(evaluate_request(wildcard, {
            "id": "data",
            "type": "external",
            "url": "data:text/javascript,console.log(1)",
        })["allowed"])
        self.assertTrue(evaluate_request(wildcard, {
            "id": "blob",
            "type": "external",
            "url": "blob:https://app.example.com/uuid",
        })["allowed"])

    def test_sha384_and_sha512_are_content_based(self):
        for algorithm in ("sha384", "sha512"):
            digest = content_digest(ORIGINAL_INLINE, algorithm)
            policy = parse_header("script-src '{}-{}'".format(algorithm, digest))
            result = evaluate_request(policy, {
                "id": algorithm,
                "type": "inline",
                "inline_text": ORIGINAL_INLINE,
            })
            self.assertTrue(result["allowed"], algorithm)

    def test_cli_writes_report_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "nested", "report.json")
            exit_code = main([
                "--policies", os.path.join(ROOT, "demo", "policies.json"),
                "--requests", os.path.join(ROOT, "demo", "requests.json"),
                "--out", output_path,
            ])
            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                written = json.load(handle)
            self.assertEqual(written["summary"]["request_count"], 12)


def parse_policy_collection(value):
    from cspaudit.parser import load_policies
    return load_policies(value)


if __name__ == "__main__":
    unittest.main()
