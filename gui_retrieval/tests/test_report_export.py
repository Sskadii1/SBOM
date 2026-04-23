from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.report_export_service import (  # noqa: E402
    _dedupe_text_items,
    export_developer_report_pdf,
    export_developer_report_pdf_for_project,
    export_stakeholder_report_pdf,
    export_stakeholder_report_pdf_for_project,
)
from backend.services.report_rendering_service import (  # noqa: E402
    render_developer_report_html,
    render_stakeholder_report_html,
)
from backend.services.report_service import (  # noqa: E402
    _apply_developer_narrative,
    _apply_stakeholder_narrative,
)
from backend.services.developer_report_builder import build_developer_report  # noqa: E402
from backend.services.stakeholder_report_builder import build_stakeholder_report  # noqa: E402


def _renderer_available() -> bool:
    if importlib.util.find_spec("weasyprint") is not None:
        return True
    browser_paths = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ]
    return any(path.exists() for path in browser_paths)


def _case(vuln_id: str, status: str) -> dict:
    return {
        "project": "demo/project",
        "scan_id": "scan-123",
        "source_commit": "abc123",
        "vuln_id": vuln_id,
        "component_name": "sample-lib",
        "component_version": "1.0.0",
        "component_id": "pkg:npm/sample-lib@1.0.0",
        "cvss": 9.1,
        "epss": 0.4,
        "kev": False,
        "severity": "critical",
        "fix_versions": ["1.1.0"],
        "dependency_depth": 1,
        "dependency_chain": ["demo/project", "sample-lib"],
        "scope": "runtime",
        "reachability_verdict": "likely_reachable",
        "call_locations": ["src/app.py:42"],
        "sink_functions": ["dangerousSink"],
        "risk_score": 88.2,
        "evidence_confidence": "high",
        "decision_tier": "fix_now",
        "status": status,
        "impact_summary": "Could affect live request handling.",
        "advisory_summary": "Advisory summary.",
        "verification_basis": "Rerun after upgrade.",
        "summary_note": "sample note",
    }


class ReportExportTests(unittest.TestCase):
    def test_dedupe_text_items_removes_duplicate_lines(self) -> None:
        items = [
            "Run checklist item A",
            " run checklist item A ",
            "Run checklist item B",
        ]
        deduped = _dedupe_text_items(items)
        self.assertEqual(deduped, ["Run checklist item A", "Run checklist item B"])

    def test_render_stakeholder_html_uses_structured_sections(self) -> None:
        report = build_stakeholder_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "resolved_pending_verify"),
            ],
        )
        _apply_stakeholder_narrative(report, use_llm=False)

        html = render_stakeholder_report_html(report)

        self.assertIn("What Needs Attention Now", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Priority Actions", html)
        self.assertIn("<table", html)
        self.assertNotIn("Why now: Why now:", html)
        self.assertIn("Decision-focused security posture summary", html)

    def test_render_developer_html_uses_structured_tables(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "under_review"),
            ],
        )
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report)

        self.assertIn("Queue Overview", html)
        self.assertIn("Remediation Briefing", html)
        self.assertIn("Immediate Remediation Clusters", html)
        self.assertIn("Technical Appendix", html)
        self.assertIn("<table", html)
        self.assertIn("Direct call evidence", html)
        self.assertIn("developer-band--briefing", html)
        self.assertIn("developer-band--cluster", html)
        self.assertIn("developer-band--verification", html)

    def test_render_html_converts_limited_markdown_in_report_prose(self) -> None:
        stakeholder = build_stakeholder_report(
            "demo/project",
            [_case("CVE-1", "new")],
        )
        _apply_stakeholder_narrative(stakeholder, use_llm=False)
        stakeholder["narrative_sections"]["what_needs_attention_now"] = (
            "**Primary evidence** is ready.\n\n"
            "- Upgrade the package\n"
            "- Re-run verification"
        )
        stakeholder["top_priority_actions"][0]["impact_basis"] = (
            "| Signal | Observation |\n"
            "| --- | --- |\n"
            "| Scope | Runtime path |\n"
            "| Owner | Platform team |"
        )

        developer = build_developer_report(
            "demo/project",
            [_case("CVE-1", "new")],
        )
        _apply_developer_narrative(developer, use_llm=False)
        developer["immediate_fix_clusters"][0]["next_action"] = (
            "1. Upgrade `sample-lib`.\n"
            "2. Re-run scans."
        )

        stakeholder_html = render_stakeholder_report_html(stakeholder)
        developer_html = render_developer_report_html(developer)

        self.assertIn("<strong>Primary evidence</strong>", stakeholder_html)
        self.assertIn("<ul>", stakeholder_html)
        self.assertIn('class="prose-table"', stakeholder_html)
        self.assertNotIn("**Primary evidence**", stakeholder_html)
        self.assertNotIn("| Signal | Observation |", stakeholder_html)
        self.assertIn("<ol>", developer_html)
        self.assertIn("<code>sample-lib</code>", developer_html)
        self.assertNotIn("1. Upgrade `sample-lib`.", developer_html)

    @unittest.skipUnless(_renderer_available(), "No supported PDF renderer is available.")
    def test_export_stakeholder_pdf_bytes(self) -> None:
        report = build_stakeholder_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "resolved_pending_verify"),
                _case("CVE-3", "verified_closed"),
            ],
        )
        _apply_stakeholder_narrative(report, use_llm=False)

        try:
            payload = export_stakeholder_report_pdf(report)
        except RuntimeError as exc:
            self.skipTest(str(exc))

        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 1200)

    @unittest.skipUnless(_renderer_available(), "No supported PDF renderer is available.")
    def test_export_developer_pdf_bytes(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "resolved_pending_verify"),
            ],
        )
        _apply_developer_narrative(report, use_llm=False)

        try:
            payload = export_developer_report_pdf(report)
        except RuntimeError as exc:
            self.skipTest(str(exc))

        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 1200)

    def test_project_export_forces_llm_on_for_stakeholder_export(self) -> None:
        report = build_stakeholder_report("demo/project", [_case("CVE-1", "new")])
        with patch("backend.services.report_service.generate_stakeholder_report", return_value=report) as generate_mock:
            with patch(
                "backend.services.report_export_service.export_stakeholder_report_pdf",
                return_value=b"%PDF-mock",
            ) as export_mock:
                payload = export_stakeholder_report_pdf_for_project("demo/project")

        self.assertEqual(payload, b"%PDF-mock")
        generate_mock.assert_called_once_with("demo/project", scan_id=None, use_llm=True)
        export_mock.assert_called_once_with(report)

    def test_project_export_forces_llm_on_for_developer_export(self) -> None:
        report = build_developer_report("demo/project", [_case("CVE-1", "new")])
        with patch("backend.services.report_service.generate_developer_report", return_value=report) as generate_mock:
            with patch(
                "backend.services.report_export_service.export_developer_report_pdf",
                return_value=b"%PDF-mock",
            ) as export_mock:
                payload = export_developer_report_pdf_for_project("demo/project")

        self.assertEqual(payload, b"%PDF-mock")
        generate_mock.assert_called_once_with(
            "demo/project",
            vuln_id=None,
            component_id=None,
            scan_id=None,
            use_llm=True,
        )
        export_mock.assert_called_once_with(report)


if __name__ == "__main__":
    unittest.main()
