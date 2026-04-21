import unittest
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.llm_service import sanitize_developer_report_narrative  # noqa: E402


class TestLlmReportSanitization(unittest.TestCase):
    def test_developer_narrative_removes_prompt_echo_and_meta_reasoning(self) -> None:
        leaked = """## Developer Remediation Summary
## Recommended Fix Plan
## Verification Steps
Rules:
- Use only facts from the provided report JSON.
Let's break down the required sections:
We should summarize triage first.
"""
        cleaned = sanitize_developer_report_narrative(leaked)
        self.assertIn("## Developer Remediation Summary", cleaned)
        self.assertIn("## Recommended Fix Plan", cleaned)
        self.assertIn("## Verification Steps", cleaned)
        self.assertNotIn("Rules:", cleaned)
        self.assertNotIn("Let's break down", cleaned)


if __name__ == "__main__":
    unittest.main()
