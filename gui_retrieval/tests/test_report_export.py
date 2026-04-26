from __future__ import annotations

import importlib.util
import re
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


def _case(
    vuln_id: str,
    status: str,
    *,
    component_name: str = "sample-lib",
    fix_versions: list[str] | None = None,
    call_locations: list[str] | None = None,
) -> dict:
    return {
        "project": "demo/project",
        "scan_id": "scan-123",
        "source_commit": "abc123",
        "vuln_id": vuln_id,
        "component_name": component_name,
        "component_version": "1.0.0",
        "component_id": f"pkg:npm/{component_name}@1.0.0",
        "cvss": 9.1,
        "epss": 0.4,
        "kev": False,
        "severity": "critical",
        "fix_versions": fix_versions or ["1.1.0"],
        "dependency_depth": 1,
        "dependency_chain": ["demo/project", component_name],
        "scope": "runtime",
        "reachability_verdict": "likely_reachable",
        "call_locations": call_locations or ["src/app.py:42"],
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
        self.assertIn('<title>Stakeholder Security Summary - demo/project</title>', html)
        self.assertIn('class="print-meta print-meta--title"', html)
        self.assertIn('class="print-meta print-meta--project"', html)
        self.assertIn('class="print-meta print-meta--generated"', html)
        self.assertIn("counter(page)", html)
        self.assertIn("counter(pages)", html)
        self.assertIn("string-set: report-title content();", html)
        self.assertIn("<table", html)
        self.assertIn('class="kv-summary-table compact-kv-table"', html)
        self.assertNotIn("Why now: Why now:", html)
        self.assertIn("Decision-focused security posture summary", html)
        self.assertLess(
            html.find("stakeholder-cover__metrics"),
            html.find("stakeholder-cover__narrative"),
        )
        self.assertIn("narrative-stack stakeholder-cover__narrative", html)
        self.assertNotIn("narrative-grid stakeholder-cover__narrative", html)
        self.assertLess(html.find("What Needs Attention Now"), html.find("Why It Matters Now"))
        self.assertLess(html.find("Why It Matters Now"), html.find("Priority Actions"))
        self.assertLess(html.find("Priority Actions"), html.find("Exposure Context"))
        self.assertLess(html.find("Exposure Context"), html.find("Action Snapshot And Impact Metrics"))
        self.assertLess(html.find("Action Snapshot And Impact Metrics"), html.find("What Remains Under Observation"))
        self.assertLess(html.find("What Remains Under Observation"), html.find("Next Verification Checkpoint"))

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
        self.assertIn("Executive Remediation Summary", html)
        self.assertIn("Immediate Remediation Queue", html)
        self.assertIn("Verification Plan", html)
        self.assertIn('<title>Developer Remediation Report - demo/project</title>', html)
        self.assertIn('class="print-meta print-meta--title"', html)
        self.assertIn('class="print-meta print-meta--project"', html)
        self.assertIn('class="print-meta print-meta--generated"', html)
        self.assertIn("counter(page)", html)
        self.assertIn("counter(pages)", html)
        self.assertIn("string-set: report-title content();", html)
        self.assertNotIn("Technical Appendix", html)
        self.assertIn("<table", html)
        self.assertIn("Direct call evidence", html)
        self.assertIn("report-card--queue", html)
        self.assertIn("stacked-report-flow", html)
        self.assertIn("stacked-report-flow--queue", html)
        self.assertNotIn("developer-band--cluster", html)
        self.assertIn('class="kv-summary-table compact-kv-table"', html)
        self.assertIn("Scope snapshot", html)
        self.assertIn("Evidence category", html)
        self.assertNotIn("Verification target", html)

    def test_render_html_limits_header_metadata_to_generated_and_project(self) -> None:
        report = build_developer_report(
            "demo/project",
            [_case("CVE-1", "new")],
        )
        report["run_id"] = "run-123"
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report)

        self.assertIn("<th>Generated</th>", html)
        self.assertIn("<th>Project</th>", html)
        self.assertNotIn("<th>Scan</th>", html)
        self.assertNotIn("<th>Report Run</th>", html)
        self.assertNotIn("<th>Narrative Layer</th>", html)
        self.assertNotIn("<th>Source Commit</th>", html)

    def test_render_developer_html_hides_appendix_by_default_but_keeps_optional_mode(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "under_review"),
            ],
        )
        _apply_developer_narrative(report, use_llm=False)

        default_html = render_developer_report_html(report)
        appendix_html = render_developer_report_html(report, include_appendix=True)

        self.assertNotIn("Technical Appendix", default_html)
        self.assertIn("Technical Appendix", appendix_html)
        self.assertIn("Operator note", appendix_html)

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
        self.assertNotIn("@@PLACEHOLDER", stakeholder_html)
        self.assertNotIn("@@PLACEHOLDER", developer_html)
        self.assertNotIn("[[[PH", stakeholder_html)
        self.assertNotIn("[[[PH", developer_html)

    def test_render_developer_html_uses_compact_appendix_when_requested(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "under_review"),
            ],
        )
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report, include_appendix=True)

        self.assertIn("Operator note", html)
        self.assertIn("report-card--queue", html)
        self.assertNotIn("Observed locations</th>", html)
        self.assertNotIn("Impact summary</th>", html)
        self.assertNotIn("Fix path available:", html)

    def test_render_compact_summary_tables_use_fixed_width_safe_structure(self) -> None:
        stakeholder = build_stakeholder_report("demo/project", [_case("CVE-1", "new")])
        developer = build_developer_report("demo/project", [_case("CVE-1", "new")])
        _apply_stakeholder_narrative(stakeholder, use_llm=False)
        _apply_developer_narrative(developer, use_llm=False)

        stakeholder_html = render_stakeholder_report_html(stakeholder)
        developer_html = render_developer_report_html(developer)

        self.assertIn('class="kv-summary-table compact-kv-table"', stakeholder_html)
        self.assertIn('class="kv-summary-table compact-kv-table"', developer_html)
        self.assertIn("compact-kv-table__label-col", stakeholder_html)
        self.assertIn("compact-kv-table__value-col", stakeholder_html)
        self.assertIn("compact-kv-table__label-col", developer_html)
        self.assertIn("compact-kv-table__value-col", developer_html)
        self.assertIn("overflow-wrap: anywhere;", developer_html)
        self.assertIn("table-layout: fixed;", developer_html)

    def test_render_html_includes_pagination_wrappers_for_compact_sections(self) -> None:
        stakeholder = build_stakeholder_report("demo/project", [_case("CVE-1", "new")])
        developer = build_developer_report("demo/project", [_case("CVE-1", "new")])
        _apply_stakeholder_narrative(stakeholder, use_llm=False)
        _apply_developer_narrative(developer, use_llm=False)

        stakeholder_html = render_stakeholder_report_html(stakeholder)
        developer_html = render_developer_report_html(developer)

        self.assertIn("keep-with-next", stakeholder_html)
        self.assertIn("compact-table-block", stakeholder_html)
        self.assertIn("checkpoint-block", stakeholder_html)
        self.assertIn("summary-block", stakeholder_html)
        self.assertIn("priority-actions__decision", stakeholder_html)
        self.assertIn("section-opening", stakeholder_html)
        self.assertIn("keep-with-next", developer_html)
        self.assertIn("compact-table-block", developer_html)
        self.assertIn("checkpoint-block", developer_html)
        self.assertIn("summary-block", developer_html)
        self.assertIn("avoid-break-inside", developer_html)
        self.assertIn("queue-card__header", developer_html)
        self.assertIn("section-opening", developer_html)
        self.assertNotRegex(stakeholder_html, r'<section class="[^"]*section-block--compact')
        self.assertNotRegex(developer_html, r'<section class="[^"]*section-block--compact')

    def test_render_developer_queue_cards_allow_page_splitting_but_keep_header_together(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "new", component_name="sample-lib", call_locations=["src/routes.py:13"]),
            ],
        )
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report)

        queue_card_match = re.search(r'<article class="([^"]*report-card--queue[^"]*)"', html)
        self.assertIsNotNone(queue_card_match)
        queue_card_classes = queue_card_match.group(1)
        self.assertNotIn("avoid-break-inside", queue_card_classes)
        self.assertNotIn("summary-block", queue_card_classes)
        self.assertIn('class="queue-card__header compact-table-block summary-block"', html)
        self.assertIn('class="stacked-report-flow stacked-report-flow--queue"', html)
        self.assertRegex(
            html,
            r'(?s)Executive Remediation Summary</h2>.*?<div class="report-table-wrap compact-table-block summary-block">',
        )

    def test_render_developer_html_merges_duplicate_clusters_and_verification_targets(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case(
                    "CVE-1",
                    "new",
                    component_name="simple-git",
                    fix_versions=["3.32.0"],
                    call_locations=["src/app.py:42"],
                ),
                _case(
                    "CVE-2",
                    "new",
                    component_name="simple-git",
                    fix_versions=["3.32.3"],
                    call_locations=["tests/test_routes.py:13"],
                ),
            ],
        )
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report)

        self.assertEqual(len(report["immediate_fix_clusters"]), 1)
        self.assertEqual(len(report["cluster_verification_targets"]), 1)
        self.assertIn("1 remediation cluster(s) currently sit in the immediate queue.", html)
        self.assertGreaterEqual(html.count("simple-git remediation cluster"), 2)
        self.assertIn("1.0.0 -&gt; 3.32.3", html)

    def test_render_developer_html_omits_per_cluster_verification_target(self) -> None:
        report = build_developer_report("demo/project", [_case("CVE-1", "new")])
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report)

        self.assertNotIn("Verification target", html)
        self.assertIn("Cluster Verification Targets", html)

    def test_render_developer_export_html_hides_verification_delta_and_targets(self) -> None:
        report = build_developer_report("demo/project", [_case("CVE-1", "new")])
        _apply_developer_narrative(report, use_llm=False)

        html = render_developer_report_html(report, include_verification_details=False)

        self.assertIn("Verification Plan", html)
        self.assertNotIn("Verification Delta", html)
        self.assertNotIn("Cluster Verification Targets", html)

    @unittest.skipUnless(_renderer_available(), "No supported PDF renderer is available.")
    def test_export_developer_pdf_handles_long_queue_card(self) -> None:
        cases = []
        for index in range(1, 10):
            cases.append(
                {
                    **_case(
                        f"CVE-{index}",
                        "new",
                        component_name="transformers",
                        fix_versions=["8cb522b4190bd556ce51be04942720650b1a3e57"],
                        call_locations=[
                            f"src/module_{index}.py:{line}"
                            for line in (10, 20, 30, 40)
                        ],
                    ),
                    "component_id": "pkg:pypi/transformers@1.0.0",
                }
            )
        report = build_developer_report("demo/project", cases)
        _apply_developer_narrative(report, use_llm=False)

        try:
            payload = export_developer_report_pdf(report)
        except RuntimeError as exc:
            self.skipTest(str(exc))

        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 1200)

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

    def test_export_developer_pdf_uses_export_specific_verification_visibility(self) -> None:
        report = build_developer_report("demo/project", [_case("CVE-1", "new")])

        with patch(
            "backend.services.report_export_service.render_developer_report_html",
            return_value="<html>developer</html>",
        ) as render_mock:
            with patch(
                "backend.services.report_export_service._render_pdf_from_html",
                return_value=b"%PDF-mock",
            ) as pdf_mock:
                payload = export_developer_report_pdf(report)

        self.assertEqual(payload, b"%PDF-mock")
        render_mock.assert_called_once_with(
            report,
            include_verification_details=False,
        )
        pdf_mock.assert_called_once_with("<html>developer</html>")


if __name__ == "__main__":
    unittest.main()
