from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models.report_status import normalize_case_status  # noqa: E402
from backend.services.evidence_service import normalize_alert_case  # noqa: E402


class ModelNormalizationTests(unittest.TestCase):
    def test_legacy_status_mapping(self) -> None:
        self.assertEqual(normalize_case_status("fix_planned"), "planned")
        self.assertEqual(normalize_case_status("mitigation_planned"), "planned")
        self.assertEqual(normalize_case_status("deferred"), "planned")
        self.assertEqual(normalize_case_status("accepted_risk"), "planned")

    def test_alert_case_summary_note_and_shape(self) -> None:
        row = {
            "project": "demo/project",
            "vuln_id": "CVE-2025-1111",
            "component": "sample-lib",
            "version": "1.0.0",
            "component_id": "pkg:npm/sample-lib@1.0.0",
            "cvss": 8.2,
            "epss": 0.22,
            "kev": False,
            "severity": "high",
            "fix_versions": ["1.0.1"],
            "scope": "runtime",
            "dependency_depth": 1,
            "reachability_verdict": "likely_reachable",
            "call_locations": ["app/main.py:12"],
            "risk_score": 77.5,
            "detail_summary": "Long detail summary for remediation guidance.",
        }
        case = normalize_alert_case(row, case_state={"status": "accepted_risk"})
        self.assertEqual(case["summary_note"], "Long detail summary for remediation guidance.")
        self.assertEqual(case["status"], "planned")
        self.assertNotIn("owner", case)
        self.assertNotIn("target_date", case)


if __name__ == "__main__":
    unittest.main()
