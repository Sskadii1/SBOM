from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.developer_report_builder import build_developer_report  # noqa: E402
from backend.services.stakeholder_report_builder import build_stakeholder_report  # noqa: E402


def _case(
    vuln_id: str,
    component_name: str,
    decision_tier: str,
    status: str,
    risk_score: float,
    *,
    reachability_verdict: str = "likely_reachable",
    fix_versions: list[str] | None = None,
    kev: bool = False,
) -> dict:
    return {
        "project": "demo/project",
        "vuln_id": vuln_id,
        "component_name": component_name,
        "component_version": "1.0.0",
        "component_id": f"pkg:npm/{component_name}@1.0.0",
        "cvss": 8.2,
        "epss": 0.21,
        "kev": kev,
        "severity": "high",
        "fix_versions": fix_versions or [],
        "dependency_depth": 1,
        "scope": "runtime",
        "reachability_verdict": reachability_verdict,
        "call_locations": [],
        "risk_score": risk_score,
        "decision_tier": decision_tier,
        "status": status,
        "summary_note": "sample note",
    }


class ReportBuilderTests(unittest.TestCase):
    def test_build_stakeholder_report_schema_and_counts(self) -> None:
        cases = [
            _case("CVE-1", "a", "fix_now", "new", 91.0, kev=True, fix_versions=["2.0.0"]),
            _case("CVE-2", "b", "monitor", "verified_closed", 35.0),
            _case("CVE-3", "c", "plan_remediation", "resolved_pending_verify", 70.0, fix_versions=["1.2.3"]),
        ]
        case_states = {
            ("demo/project", "CVE-0", "pkg:npm/z@1.0.0"): {
                "status": "resolved_pending_verify",
            }
        }
        report = build_stakeholder_report("demo/project", cases, case_states=case_states)

        self.assertEqual(report["report_type"], "stakeholder")
        self.assertEqual(report["posture_summary"]["total_cases"], 3)
        self.assertTrue(report["top_priority_actions"])
        self.assertTrue(all("recommended_action" in item for item in report["top_priority_actions"]))
        self.assertTrue(
            any("upgrade to a fixed version" in str(item.get("recommended_action", "")).lower() for item in report["top_priority_actions"])
        )
        self.assertTrue(report["impact_summary"]["runtime_affected_cases"] >= 1)
        self.assertTrue(all("case_count" in item for item in report["action_buckets"]))
        self.assertTrue(all("recommended_action" in item for item in report["action_buckets"]))
        self.assertTrue(
            any("known fix versions" in str(item.get("recommended_action", "")).lower() for item in report["action_buckets"])
        )
        self.assertEqual(report["status_snapshot"]["verified_closed"], 1)
        self.assertEqual(report["status_snapshot"]["resolved_pending_verify"], 2)
        self.assertIn("guidance", report["next_verification_checkpoint"])

    def test_build_developer_report_bucketing(self) -> None:
        cases = [
            _case("CVE-1", "a", "fix_now", "new", 91.0, fix_versions=["2.0.0"]),
            _case("CVE-2", "b", "mitigate", "under_review", 72.0),
            _case("CVE-3", "c", "monitor", "planned", 20.0),
        ]
        report = build_developer_report("demo/project", cases)

        self.assertEqual(report["report_type"], "developer")
        self.assertEqual(report["triage_summary"]["total_cases"], 3)
        self.assertEqual(report["triage_summary"]["fix_now"], 1)
        self.assertEqual(report["triage_summary"]["investigate_next"], 1)
        self.assertEqual(report["triage_summary"]["monitor"], 1)
        self.assertEqual(len(report["technical_findings"]), 3)
        self.assertTrue(report["dependency_context"]["direct_dependency_cases"] >= 1)
        self.assertIn("confirmed_reachable", report["reachability_evidence"])
        self.assertTrue(report["recommended_fix"])
        self.assertTrue(report["verification_steps"])


if __name__ == "__main__":
    unittest.main()
