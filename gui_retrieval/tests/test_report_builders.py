from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.developer_report_builder import build_developer_report  # noqa: E402
from backend.services.report_presentation_service import (  # noqa: E402
    select_preferred_fix_version,
    verification_delta_has_baseline,
    verification_delta_is_meaningful,
)
from backend.services.report_vocabulary_service import (  # noqa: E402
    normalize_labeled_text,
    present_decision_tier,
    present_reachability,
)
from backend.services.report_service import (  # noqa: E402
    _apply_developer_narrative,
    _apply_stakeholder_narrative,
)
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
    call_locations: list[str] | None = None,
    summary_note: str = "sample note",
) -> dict:
    return {
        "project": "demo/project",
        "scan_id": "scan-123",
        "source_commit": "abc123",
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
        "dependency_chain": ["demo/project", component_name],
        "scope": "runtime",
        "reachability_verdict": reachability_verdict,
        "call_locations": call_locations or [],
        "sink_functions": ["dangerousSink"],
        "risk_score": risk_score,
        "evidence_confidence": "high",
        "impact_summary": "Could affect the request handling path.",
        "advisory_summary": "Advisory summary.",
        "verification_basis": "Rerun reachability after upgrade.",
        "decision_tier": decision_tier,
        "status": status,
        "summary_note": summary_note,
    }


class ReportBuilderTests(unittest.TestCase):
    def test_build_stakeholder_report_schema_and_counts(self) -> None:
        cases = [
            _case(
                "CVE-1",
                "a",
                "fix_now",
                "new",
                91.0,
                kev=True,
                fix_versions=["2.0.0"],
                reachability_verdict="confirmed_reachable",
                call_locations=["src/server/app.py:12"],
            ),
            _case(
                "CVE-2",
                "b",
                "monitor",
                "verified_closed",
                35.0,
                reachability_verdict="likely_unreachable",
            ),
            _case(
                "CVE-3",
                "c",
                "plan_remediation",
                "planned",
                70.0,
                fix_versions=["1.2.3"],
                reachability_verdict="likely_reachable",
                call_locations=["tests/test_flow.py:55"],
            ),
        ]
        report = build_stakeholder_report("demo/project", cases)

        self.assertEqual(report["report_type"], "stakeholder")
        self.assertEqual(report["posture_summary"]["total_cases"], 2)
        self.assertEqual(report["posture_summary"]["reachable_count"], 1)
        self.assertEqual(report["posture_summary"]["likely_reachable_count"], 1)
        self.assertEqual(report["posture_summary"]["overall_posture"], "elevated")
        self.assertTrue(report["affected_areas"])
        self.assertTrue(report["top_priority_actions"])
        self.assertLessEqual(len(report["top_priority_actions"]), 3)
        self.assertTrue(
            all(item["decision_tier"] in {"fix_now", "plan_remediation"} for item in report["top_priority_actions"])
        )
        self.assertTrue(all("affected_area" in item for item in report["top_priority_actions"]))
        self.assertTrue(all("why_now" in item for item in report["top_priority_actions"]))
        self.assertTrue(all("impact_basis" in item for item in report["top_priority_actions"]))
        self.assertTrue(
            all(not str(item["why_now"]).lower().startswith("why now:") for item in report["top_priority_actions"])
        )
        self.assertEqual(report["impact_summary"]["reachable_or_likely_count"], 2)
        self.assertIn("high_exposure_areas", report["impact_summary"])
        self.assertEqual(report["current_action_snapshot"]["fix_now_count"], 1)
        self.assertEqual(report["current_action_snapshot"]["plan_remediation_count"], 1)
        self.assertTrue(report["recommended_management_actions"])
        self.assertIn("trigger", report["next_verification_checkpoint"])
        self.assertIn("goal", report["next_verification_checkpoint"])
        self.assertIn("note", report["next_verification_checkpoint"])
        self.assertNotIn("call_locations", str(report))

    def test_stakeholder_areas_collapse_when_only_generic_mapping_exists(self) -> None:
        cases = [
            _case("CVE-1", "a", "fix_now", "new", 91.0, call_locations=["tests/a.py:10"]),
            _case("CVE-2", "b", "plan_remediation", "planned", 70.0, call_locations=["spec/b.py:22"]),
        ]
        report = build_stakeholder_report("demo/project", cases)
        self.assertEqual(len(report["affected_areas"]), 1)
        self.assertEqual(report["affected_areas"][0]["area_name"], "Repository-Wide Exposure")

    def test_build_developer_report_schema_and_evidence_scope(self) -> None:
        cases = [
            _case(
                "CVE-1",
                "a",
                "fix_now",
                "new",
                91.0,
                fix_versions=["2.0.0"],
                reachability_verdict="confirmed_reachable",
                call_locations=["src/app.py:10", "tests/test_app.py:11"],
            ),
            _case(
                "CVE-2",
                "b",
                "mitigate",
                "under_review",
                72.0,
                reachability_verdict="no_sink_data",
            ),
            _case(
                "CVE-3",
                "c",
                "monitor",
                "planned",
                20.0,
                reachability_verdict="likely_unreachable",
                call_locations=["tests/test_only.py:22"],
            ),
        ]
        report = build_developer_report("demo/project", cases)

        self.assertEqual(report["report_type"], "developer")
        self.assertEqual(report["triage_summary"]["total_cases"], 3)
        self.assertEqual(report["triage_summary"]["fix_now_count"], 1)
        self.assertEqual(report["triage_summary"]["plan_remediation_count"], 0)
        self.assertEqual(report["triage_summary"]["mitigate_count"], 1)
        self.assertEqual(report["triage_summary"]["monitor_count"], 1)
        self.assertEqual(report["triage_summary"]["confirmed_count"], 1)
        self.assertEqual(report["triage_summary"]["no_sink_data_count"], 1)
        self.assertEqual(len(report["immediate_fix_queue"]), 1)
        self.assertTrue(report["immediate_fix_queue"][0]["production_evidence"])
        self.assertFalse(report["immediate_fix_queue"][0]["test_only_evidence"])
        self.assertTrue(report["planned_upgrade_backlog"]["top_backlog_items"])
        self.assertIn("verification_delta", report)
        self.assertTrue(report["verification_checklist"])
        self.assertEqual(len(report["detailed_technical_findings"]), 3)
        self.assertIn("technical_appendix", report)
        self.assertNotIn("verification_changes", report["technical_appendix"])
        self.assertNotIn("recommended_management_actions", report)
        self.assertLessEqual(len(report["planned_upgrade_backlog"]["top_backlog_items"]), 3)

    def test_fallback_narratives_enforce_audience_separation(self) -> None:
        stakeholder = build_stakeholder_report(
            "demo/project",
            [
                _case(
                    "CVE-1",
                    "a",
                    "fix_now",
                    "new",
                    91.0,
                    fix_versions=["2.0.0"],
                    reachability_verdict="likely_reachable",
                    call_locations=["src/server/app.py:12"],
                )
            ],
        )
        developer = build_developer_report(
            "demo/project",
            [
                _case(
                    "CVE-1",
                    "a",
                    "fix_now",
                    "new",
                    91.0,
                    fix_versions=["2.0.0"],
                    reachability_verdict="likely_reachable",
                    call_locations=["src/server/app.py:12"],
                )
            ],
        )

        _apply_stakeholder_narrative(stakeholder, use_llm=False)
        _apply_developer_narrative(developer, use_llm=False)

        stakeholder_narrative = stakeholder.get("narrative", "")
        developer_narrative = developer.get("narrative", "")

        self.assertIn("## What Needs Attention Now", stakeholder_narrative)
        self.assertIn("## What Action Or Approval Is Needed Next", stakeholder_narrative)
        self.assertNotIn("src/server/app.py:12", stakeholder_narrative)
        self.assertNotIn("confirmed_reachable", stakeholder_narrative)
        self.assertNotIn("fix_now", stakeholder_narrative.lower())
        self.assertIn("## Queue Overview", developer_narrative)
        self.assertIn("## Strongest Evidence", developer_narrative)
        self.assertIn("## Verification Guidance", developer_narrative)
        self.assertNotIn("Approve immediate remediation work", developer_narrative)
        self.assertNotIn("no_sink_data", developer_narrative)

    def test_vocabulary_layer_translates_internal_labels(self) -> None:
        self.assertEqual(
            present_reachability("confirmed_reachable", "stakeholder"),
            "Direct evidence of use",
        )
        self.assertEqual(
            present_reachability("no_sink_data", "developer", style="sentence"),
            "does not have sink-level evidence yet, so practical reachability cannot be concluded",
        )
        self.assertEqual(
            present_decision_tier("fix_now", "stakeholder"),
            "Act in current release",
        )
        self.assertEqual(
            normalize_labeled_text("Why now", "Why now: Why now: direct evidence exists."),
            "direct evidence exists.",
        )

    def test_preferred_fix_version_uses_highest_stable_version(self) -> None:
        self.assertEqual(
            select_preferred_fix_version(["0.31.0", "1.13.5", "1.13.5-rc1"]),
            "1.13.5",
        )

    def test_verification_delta_helpers_detect_meaningful_changes(self) -> None:
        empty_delta = {
            "baseline_scan_id": None,
            "current_scan_id": "scan-2",
            "resolved_cases": 0,
            "risk_decreased_cases": 0,
            "verdict_improved_cases": 0,
        }
        baseline_only = {
            "baseline_scan_id": "scan-1",
            "current_scan_id": "scan-2",
            "resolved_cases": 0,
            "risk_decreased_cases": 0,
            "verdict_improved_cases": 0,
        }
        improved = {
            "baseline_scan_id": "scan-1",
            "current_scan_id": "scan-2",
            "resolved_cases": 1,
            "risk_decreased_cases": 0,
            "verdict_improved_cases": 0,
        }

        self.assertFalse(verification_delta_has_baseline(empty_delta))
        self.assertFalse(verification_delta_is_meaningful(empty_delta))
        self.assertTrue(verification_delta_has_baseline(baseline_only))
        self.assertFalse(verification_delta_is_meaningful(baseline_only))
        self.assertTrue(verification_delta_is_meaningful(improved))


if __name__ == "__main__":
    unittest.main()
