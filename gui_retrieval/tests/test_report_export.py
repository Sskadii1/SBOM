from __future__ import annotations

import sys
import unittest
import importlib.util
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.stakeholder_report_builder import build_stakeholder_report  # noqa: E402

try:
    from backend.services.report_export_service import export_stakeholder_report_pdf  # noqa: E402
except Exception:  # pragma: no cover - optional dependency in local env.
    export_stakeholder_report_pdf = None  # type: ignore[assignment]


def _case(vuln_id: str, status: str) -> dict:
    return {
        "project": "demo/project",
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
        "scope": "runtime",
        "reachability_verdict": "likely_reachable",
        "call_locations": [],
        "risk_score": 88.2,
        "decision_tier": "fix_now",
        "status": status,
        "summary_note": "sample note",
    }


class ReportExportTests(unittest.TestCase):
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
        report["narrative"] = "## Executive Security Summary\nsample\n\n## Priority Actions\nsample\n\n## Impact Summary\nsample\n\n## Action Buckets\nsample\n\n## Status Snapshot\nsample\n\n## Next Verification Checkpoint\nsample"
        payload = export_stakeholder_report_pdf(report)  # type: ignore[operator]
        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 800)


if __name__ == "__main__":
    unittest.main()
