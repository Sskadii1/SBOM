from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models.decision_tiering import (  # noqa: E402
    decision_tier_rationale,
    normalize_decision_tier,
    recommend_decision_tier,
)


class DecisionTieringTests(unittest.TestCase):
    def test_recommend_fix_now_for_kev_and_confirmed_reachable(self) -> None:
        tier = recommend_decision_tier(
            kev=True,
            risk_score=92.0,
            reachability_verdict="confirmed_reachable",
            fix_versions=["1.2.3"],
        )
        self.assertEqual(tier, "fix_now")

    def test_recommend_fix_now_when_likely_reachable_without_fix(self) -> None:
        tier = recommend_decision_tier(
            kev=False,
            risk_score=70.0,
            reachability_verdict="likely_reachable",
            fix_versions=[],
        )
        self.assertEqual(tier, "fix_now")

    def test_recommend_fix_now_when_confirmed_reachable_even_with_low_risk(self) -> None:
        tier = recommend_decision_tier(
            kev=False,
            risk_score=20.0,
            reachability_verdict="confirmed_reachable",
            fix_versions=[],
        )
        self.assertEqual(tier, "fix_now")

    def test_recommend_plan_remediation_for_elevated_risk_with_fix(self) -> None:
        tier = recommend_decision_tier(
            kev=False,
            risk_score=67.0,
            reachability_verdict="likely_unreachable",
            fix_versions=["1.2.3"],
        )
        self.assertEqual(tier, "plan_remediation")

    def test_recommend_mitigate_for_high_risk_without_fix(self) -> None:
        tier = recommend_decision_tier(
            kev=False,
            risk_score=80.0,
            reachability_verdict="no_sink_data",
            fix_versions=[],
        )
        self.assertEqual(tier, "mitigate")

    def test_rationale_mentions_kev_when_fix_now(self) -> None:
        rationale = decision_tier_rationale(
            "fix_now",
            kev=True,
            risk_score=92.0,
            reachability_verdict="confirmed_reachable",
            fix_versions=["1.2.3"],
        )
        self.assertIn("KEV", rationale)

    def test_normalize_falls_back_to_default(self) -> None:
        self.assertEqual(normalize_decision_tier("invalid-tier"), "monitor")


if __name__ == "__main__":
    unittest.main()
