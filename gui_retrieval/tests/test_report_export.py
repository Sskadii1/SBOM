from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.developer_report_builder import build_developer_report  # noqa: E402
from backend.services.stakeholder_report_builder import build_stakeholder_report  # noqa: E402

try:
    from backend.services.report_export_service import (  # noqa: E402
        _dedupe_text_items,
        _extract_markdown_section,
        export_developer_report_pdf,
        export_stakeholder_report_pdf,
    )
except Exception:
    _dedupe_text_items = None  # type: ignore[assignment]
    _extract_markdown_section = None  # type: ignore[assignment]
    export_developer_report_pdf = None  # type: ignore[assignment]
    export_stakeholder_report_pdf = None  # type: ignore[assignment]


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
    @unittest.skipIf(
        _extract_markdown_section is None,
        "report_export_service is unavailable.",
    )
    def test_extract_markdown_section_returns_empty_when_header_missing(self) -> None:
        markdown = "## Executive Summary\nOnly executive section exists."
        section = _extract_markdown_section(markdown, "Impact Summary")  # type: ignore[operator]
        self.assertEqual(section, "")

    @unittest.skipIf(
        _dedupe_text_items is None,
        "report_export_service is unavailable.",
    )
    def test_dedupe_text_items_removes_duplicate_lines(self) -> None:
        items = [
            "Run checklist item A",
            " run checklist item A ",
            "Run checklist item B",
        ]
        deduped = _dedupe_text_items(items)  # type: ignore[operator]
        self.assertEqual(deduped, ["Run checklist item A", "Run checklist item B"])

    @unittest.skipIf(
        export_stakeholder_report_pdf is None or importlib.util.find_spec("fpdf") is None,
        "fpdf2 is not installed.",
    )
    def test_export_stakeholder_pdf_bytes(self) -> None:
        report = build_stakeholder_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "resolved_pending_verify"),
                _case("CVE-3", "verified_closed"),
            ],
        )
        report["narrative"] = (
            "## Executive Summary\nsample\n\n"
            "## Impact Summary\nsample\n\n"
            "## Recommended Management Actions\nsample"
        )
        payload = export_stakeholder_report_pdf(report)  # type: ignore[operator]
        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 800)

    @unittest.skipIf(
        export_developer_report_pdf is None or importlib.util.find_spec("fpdf") is None,
        "fpdf2 is not installed.",
    )
    def test_export_developer_pdf_bytes(self) -> None:
        report = build_developer_report(
            "demo/project",
            [
                _case("CVE-1", "new"),
                _case("CVE-2", "resolved_pending_verify"),
            ],
        )
        report["narrative"] = (
            "## Triage Overview\nsample\n\n"
            "## Immediate Fix Rationale\nsample"
        )
        payload = export_developer_report_pdf(report)  # type: ignore[operator]
        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 800)


if __name__ == "__main__":
    unittest.main()
