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
        leaked = """## Queue Overview
## Strongest Evidence
## Immediate Next Steps
## Verification Guidance
## What Is Still Uncertain Or Deferred
Writing style:
- Use only facts from the provided report JSON.
Let's break down the required sections:
We should summarize triage first.
"""
        cleaned = sanitize_developer_report_narrative(leaked)
        self.assertIn("## Queue Overview", cleaned)
        self.assertIn("## Verification Guidance", cleaned)
        self.assertNotIn("Writing style:", cleaned)
        self.assertNotIn("Let's break down", cleaned)

    def test_stakeholder_narrative_normalizes_to_new_sections(self) -> None:
        leaked = """## What Needs Attention Now
## Why It Matters Now
## What Action Or Approval Is Needed Next
## What Remains Under Observation
Forbidden behavior:
- Use only facts from the provided report JSON.
"""
        cleaned = sanitize_stakeholder_report_narrative(leaked)
        self.assertIn("## What Needs Attention Now", cleaned)
        self.assertIn("## Why It Matters Now", cleaned)
        self.assertIn("## What Action Or Approval Is Needed Next", cleaned)
        self.assertIn("## What Remains Under Observation", cleaned)
        self.assertNotIn("Forbidden behavior:", cleaned)


if __name__ == "__main__":
    unittest.main()
