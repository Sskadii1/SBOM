from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.verification_service import build_verification_delta  # noqa: E402


class VerificationDeltaTests(unittest.TestCase):
    def test_delta_detects_improvement_and_regression(self) -> None:
        old_cases = [
            {
                "project": "demo/project",
                "vuln_id": "CVE-1",
                "component_id": "pkg:npm/a@1.0.0",
                "risk_score": 90.0,
                "reachability_verdict": "confirmed_reachable",
                "fix_available": False,
            },
            {
                "project": "demo/project",
                "vuln_id": "CVE-2",
                "component_id": "pkg:npm/b@1.0.0",
                "risk_score": 40.0,
                "reachability_verdict": "likely_unreachable",
                "fix_available": True,
            },
        ]
        new_cases = [
            {
                "project": "demo/project",
                "vuln_id": "CVE-1",
                "component_id": "pkg:npm/a@1.0.0",
                "risk_score": 65.0,
                "reachability_verdict": "likely_reachable",
                "fix_available": True,
            },
            {
                "project": "demo/project",
                "vuln_id": "CVE-3",
                "component_id": "pkg:npm/c@1.0.0",
                "risk_score": 88.0,
                "reachability_verdict": "confirmed_reachable",
                "fix_available": False,
            },
        ]

        delta = build_verification_delta(
            old_cases,
            new_cases,
            baseline_scan_id="scan-old",
            current_scan_id="scan-new",
        )
        summary = delta["summary"]

        self.assertEqual(summary["baseline_case_count"], 2)
        self.assertEqual(summary["current_case_count"], 2)
        self.assertEqual(summary["added_cases"], 1)
        self.assertEqual(summary["resolved_cases"], 1)
        self.assertEqual(summary["risk_decreased"], 1)
        self.assertEqual(summary["verdict_improved"], 1)
        self.assertEqual(summary["fix_available_increased"], 1)
        self.assertEqual(len(delta["changes"]), 3)
        self.assertTrue(all("closure_recommendation" in row for row in delta["changes"]))


if __name__ == "__main__":
    unittest.main()
