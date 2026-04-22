from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backend.config as config  # noqa: E402
from backend.services.case_state_service import (  # noqa: E402
    bootstrap_default_states,
    get_case_state,
    get_case_states,
    upsert_case_state,
)
from backend.services.evidence_service import recompute_and_overwrite_case_state_tiers  # noqa: E402
from backend.services.verification_service import sync_case_status_with_previous_snapshot  # noqa: E402


def _sample_case(vuln_id: str, component_id: str | None) -> dict:
    return {
        "project": "demo/project",
        "vuln_id": vuln_id,
        "component_name": "pkg",
        "component_version": "1.0.0",
        "component_id": component_id,
        "cvss": 8.1,
        "epss": 0.2,
        "kev": False,
        "severity": "high",
        "fix_versions": ["1.0.1"],
        "dependency_depth": 1,
        "scope": "runtime",
        "reachability_verdict": "likely_reachable",
        "call_locations": [],
        "risk_score": 75.0,
        "decision_tier": "plan_remediation",
        "status": "new",
        "summary_note": "sample",
    }


class CaseStateServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_db = config.CVE_SINKS_DB
        self._tmp_dir = Path("gui_retrieval/tests/.tmp")
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        self._tmp_db = self._tmp_dir / f"test_case_state_{uuid.uuid4().hex}.db"
        config.CVE_SINKS_DB = self._tmp_db

    def tearDown(self) -> None:
        config.CVE_SINKS_DB = self._original_db
        if self._tmp_db.exists():
            try:
                self._tmp_db.unlink()
            except PermissionError:
                pass

    def test_upsert_and_get_case_state(self) -> None:
        saved = upsert_case_state(
            "demo/project",
            "CVE-2024-0001",
            None,
            status="under_review",
        )
        self.assertEqual(saved["status"], "under_review")
        loaded = get_case_state("demo/project", "CVE-2024-0001", None)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded["status"], "under_review")

    def test_bootstrap_default_states(self) -> None:
        cases = [
            _sample_case("CVE-2024-0001", "pkg:npm/a@1.0.0"),
            _sample_case("CVE-2024-0002", None),
        ]
        inserted = bootstrap_default_states("demo/project", cases)
        self.assertEqual(inserted, 2)

        all_states = get_case_states("demo/project")
        self.assertEqual(len(all_states), 2)

    def test_recompute_overwrites_legacy_decision_tier(self) -> None:
        upsert_case_state(
            "demo/project",
            "CVE-2024-0009",
            "pkg:npm/legacy@1.0.0",
            decision_tier="monitor",
            status="under_review",
        )

        rows = [
            {
                "project": "demo/project",
                "vuln_id": "CVE-2024-0009",
                "component": "legacy",
                "version": "1.0.0",
                "component_id": "pkg:npm/legacy@1.0.0",
                "cvss": 5.0,
                "epss": 0.05,
                "kev": False,
                "fix_versions": [],
                "dependency_depth": 1,
                "scope": "runtime",
                "reachability_verdict": "confirmed_reachable",
                "call_locations": ["app.py:10"],
                "risk_score": 50.0,
            }
        ]

        summary = recompute_and_overwrite_case_state_tiers("demo/project", rows)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["changed"], 1)

        state = get_case_state("demo/project", "CVE-2024-0009", "pkg:npm/legacy@1.0.0")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(state["decision_tier"], "fix_now")
        self.assertEqual(state["status"], "under_review")

    def test_sync_status_with_previous_snapshot(self) -> None:
        project = "demo/project"
        upsert_case_state(
            project,
            "CVE-2024-0101",
            "pkg:npm/a@1.0.0",
            status="in_progress",
            decision_tier="fix_now",
        )

        current_cases = [
            _sample_case("CVE-2024-0101", "pkg:npm/a@1.0.0"),  # existing -> unchanged
            _sample_case("CVE-2024-0103", "pkg:npm/c@1.0.0"),  # new case
        ]

        summary = sync_case_status_with_previous_snapshot(project, current_cases)
        self.assertEqual(summary["new_cases"], 1)
        self.assertEqual(summary["reopened_cases"], 0)
        self.assertEqual(summary["resolved_cases"], 0)
        self.assertTrue(summary["status_updates"] >= 1)

        existing = get_case_state(project, "CVE-2024-0101", "pkg:npm/a@1.0.0")
        self.assertIsNotNone(existing)
        assert existing is not None
        self.assertEqual(existing["status"], "in_progress")

        new_case = get_case_state(project, "CVE-2024-0103", "pkg:npm/c@1.0.0")
        self.assertIsNotNone(new_case)
        assert new_case is not None
        self.assertEqual(new_case["status"], "new")


if __name__ == "__main__":
    unittest.main()
