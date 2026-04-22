import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.llm_service import (  # noqa: E402
    sanitize_developer_report_narrative,
    sanitize_stakeholder_report_narrative,
)


class TestLlmReportSanitization(unittest.TestCase):
    def test_developer_narrative_removes_prompt_echo_and_meta_reasoning(self) -> None:
        leaked = """## Triage Overview
## Immediate Fix Rationale
Rules:
- Use only facts from the provided report JSON.
Let's break down the required sections:
We should summarize triage first.
"""
        cleaned = sanitize_developer_report_narrative(leaked)
        self.assertIn("## Triage Overview", cleaned)
        self.assertIn("## Immediate Fix Rationale", cleaned)
        self.assertNotIn("Rules:", cleaned)
        self.assertNotIn("Let's break down", cleaned)

    def test_stakeholder_narrative_normalizes_to_new_sections(self) -> None:
        leaked = """## Executive Summary
## Impact Summary
## Recommended Management Actions
Rules:
- Use only facts from the provided report JSON.
"""
        cleaned = sanitize_stakeholder_report_narrative(leaked)
        self.assertIn("## Executive Summary", cleaned)
        self.assertIn("## Impact Summary", cleaned)
        self.assertIn("## Recommended Management Actions", cleaned)
        self.assertNotIn("Rules:", cleaned)


if __name__ == "__main__":
    unittest.main()
