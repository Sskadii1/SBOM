"""
PDF export helpers for report-driven outputs.
"""

from __future__ import annotations

import re
from typing import Any

from backend.models import DeveloperReport, StakeholderReport
from backend.services.report_presentation_service import (
    verification_delta_is_meaningful,
)

_REPORT_HEADER_NAMES = {
    "executive summary",
    "impact summary",
    "recommended management actions",
    "triage overview",
    "immediate fix rationale",
}

_UNICODE_REPLACEMENTS = {
    "\u2013": "-",
    "\u2014": "-",
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2026": "...",
    "\u2192": "->",
}


def _safe_text(value: Any) -> str:
    text = str(value) if value is not None else ""
    for src, dst in _UNICODE_REPLACEMENTS.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _fmt_number(value: Any) -> str:
    try:
        return str(int(value))
    except Exception:
        return "0"


def _fmt_decimal(value: Any, digits: int = 1) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except Exception:
        return "N/A"


def _markdown_to_plain_text(value: Any) -> str:
    """
    Convert lightweight Markdown content to plain text for PDF rendering.
    """
    text = _safe_text(value)
    if not text.strip():
        return ""

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"\1", text)
    text = re.sub(r"(?<!_)_([^_]+)_(?!_)", r"\1", text)

    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            lines.append("")
            continue
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"^[-*+]\s+", "- ", line)
        normalized = line.strip().rstrip(":").lower()
        if normalized in _REPORT_HEADER_NAMES:
            continue
        line = re.sub(r"\s+", " ", line).strip()
        lines.append(line)

    plain = "\n".join(lines)
    plain = re.sub(r"\n{3,}", "\n\n", plain)
    return plain.strip()


def _extract_markdown_section(markdown: Any, section_title: str) -> str:
    text = str(markdown) if markdown is not None else ""
    if not text.strip():
        return ""

    header_pattern = re.compile(rf"(?im)^\s*#{1,6}\s*{re.escape(section_title)}\s*$")
    match = header_pattern.search(text)
    if not match:
        return ""

    body_start = match.end()
    remaining = text[body_start:]
    next_header = re.search(r"(?im)^\s*#{1,6}\s+.+$", remaining)
    if next_header:
        return remaining[: next_header.start()].strip()
    return remaining.strip()


def _normalized_text_signature(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def _dedupe_records(
    records: list[dict[str, Any]],
    signature_builder: Any,
) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        signature = str(signature_builder(record) or "").strip().lower()
        if not signature:
            signature = str(len(unique))
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(record)
    return unique


def _dedupe_text_items(values: list[Any]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        signature = _normalized_text_signature(text)
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(text)
    return unique


def _build_pdf(
    title: str,
    project: str,
    generated_at: str,
    block_renderer: Any,
) -> bytes:
    try:
        from fpdf import FPDF
    except Exception as exc:
        raise RuntimeError("PDF export requires `fpdf2` to be installed.") from exc

    class _PDF(FPDF):
        header_project: str = ""
        footer_generated_at: str = ""

        def header(self) -> None:
            self.set_draw_color(203, 213, 225)
            self.set_line_width(0.4)
            self.line(self.l_margin, 10, self.w - self.r_margin, 10)
            self.set_xy(self.l_margin, 12)
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(30, 41, 59)
            self.cell(0, 6, _safe_text(title), ln=1)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 5, _safe_text(self.header_project), ln=1)
            self.ln(1)

        def footer(self) -> None:
            self.set_y(-14)
            self.set_draw_color(203, 213, 225)
            self.set_line_width(0.4)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 116, 139)
            self.ln(1)
            self.cell(0, 5, _safe_text(self.footer_generated_at), align="L")
            self.cell(0, 5, _safe_text(f"Page {self.page_no()}"), align="R")

    def page_text_width(pdf: _PDF) -> float:
        return max(float(pdf.w - pdf.l_margin - pdf.r_margin), 20.0)

    def add_paragraph(pdf: _PDF, text: Any, line_height: float = 6, indent: float = 0.0) -> None:
        width = max(page_text_width(pdf) - indent, 20.0)
        pdf.set_x(pdf.l_margin + indent)
        pdf.multi_cell(width, line_height, _safe_text(text))
        pdf.set_x(pdf.l_margin)

    def add_block_title(pdf: _PDF, title: str) -> None:
        pdf.ln(2.5)
        pdf.set_x(pdf.l_margin)
        pdf.set_fill_color(30, 64, 175)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(page_text_width(pdf), 8, _safe_text(title), ln=1, fill=True)
        pdf.set_text_color(17, 24, 39)
        pdf.set_font("Helvetica", "", 10)
        pdf.ln(0.8)

    def add_kv(pdf: _PDF, key: str, value: Any) -> None:
        add_paragraph(pdf, f"{key}: {_safe_text(value)}", line_height=6, indent=2.0)

    pdf = _PDF()
    pdf.header_project = f"Project: {project}"
    pdf.footer_generated_at = f"Generated: {generated_at}"
    pdf.set_margins(16, 24, 16)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_title(_safe_text(f"{title} - {project}"))
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(15, 23, 42)
    add_paragraph(pdf, "Generated Report Snapshot", line_height=8)
    pdf.set_font("Helvetica", "", 10)
    add_paragraph(pdf, f"Project: {project}", line_height=6.5, indent=2.0)
    add_paragraph(pdf, f"Generated At: {generated_at}", line_height=6.5, indent=2.0)
    block_renderer(pdf, add_block_title, add_kv, add_paragraph)

    try:
        payload = pdf.output(dest="S")
    except TypeError:
        payload = pdf.output()

    if isinstance(payload, str):
        return payload.encode("latin-1", errors="replace")
    if isinstance(payload, bytearray):
        return bytes(payload)
    return bytes(payload)


def export_stakeholder_report_pdf(report: StakeholderReport) -> bytes:
    """
    Export one stakeholder report object to a lightweight PDF payload.
    """

    project = _safe_text(report.get("project", "unknown-project"))
    generated_at = _safe_text(report.get("generated_at", "unknown-time"))

    def _render_blocks(pdf: Any, add_block_title: Any, add_kv: Any, add_paragraph: Any) -> None:
        if report.get("run_id"):
            add_paragraph(pdf, f"Run ID: {report.get('run_id')}", line_height=6.5, indent=2.0)
        if report.get("scan_id"):
            add_paragraph(pdf, f"Scan ID: {report.get('scan_id')}", line_height=6.5, indent=2.0)
        if report.get("source_commit"):
            add_paragraph(pdf, f"Source Commit: {report.get('source_commit')}", line_height=6.5, indent=2.0)

        posture = report.get("posture_summary") or {}
        executive_text = _markdown_to_plain_text(
            _extract_markdown_section(report.get("narrative"), "Executive Summary")
        )
        impact_section_text = _markdown_to_plain_text(
            _extract_markdown_section(report.get("narrative"), "Impact Summary")
        )
        management_text = _markdown_to_plain_text(
            _extract_markdown_section(report.get("narrative"), "Recommended Management Actions")
        )

        add_block_title(pdf, "Affected Project Areas")
        affected_areas = _dedupe_records(
            [dict(item) for item in (report.get("affected_areas") or [])],
            lambda item: str(item.get("area_name") or "").strip().lower(),
        )
        if not affected_areas:
            add_paragraph(pdf, "No affected project areas available.", line_height=6, indent=2.0)
        else:
            for item in affected_areas[:3]:
                add_paragraph(
                    pdf,
                    (
                        f"- {item.get('area_name', 'Unknown area')}: { _fmt_number(item.get('case_count')) } case(s), "
                        f"{ _fmt_number(item.get('reachable_or_likely_count')) } reachable/likely. "
                        f"Key CVEs: {', '.join(item.get('key_cves') or []) or 'No evidence provided.'}"
                    ),
                    line_height=6,
                    indent=2.0,
                )
                add_paragraph(
                    pdf,
                    item.get("focus_reason") or "No evidence provided.",
                    line_height=6,
                    indent=4.0,
                )

        if executive_text:
            add_block_title(pdf, "Executive Summary")
            add_paragraph(pdf, executive_text, line_height=6, indent=2.0)

        top_actions = _dedupe_records(
            [dict(item) for item in (report.get("top_priority_actions") or [])],
            lambda item: (
                f"{str(item.get('vuln_id') or '').strip().lower()}|"
                f"{str(item.get('component') or '').strip().lower()}|"
                f"{str(item.get('target_version') or '').strip().lower()}|"
                f"{str(item.get('affected_area') or '').strip().lower()}"
            ),
        )
        if top_actions:
            add_block_title(pdf, "Top Priority Actions")
            for item in top_actions[:3]:
                add_paragraph(
                    pdf,
                    (
                        f"- {item.get('vuln_id', 'N/A')} | {item.get('component', 'N/A')} "
                        f"{item.get('current_version') or 'unknown'} -> {item.get('target_version') or 'investigate'} "
                        f"| tier={item.get('decision_tier', 'N/A')} | area={item.get('affected_area', 'N/A')}"
                    ),
                    line_height=6,
                    indent=2.0,
                )
                add_paragraph(pdf, f"Why now: {item.get('why_now') or 'No evidence provided.'}", line_height=6, indent=4.0)
                add_paragraph(pdf, f"Impact: {item.get('impact_basis') or 'No evidence provided.'}", line_height=6, indent=4.0)

        add_block_title(pdf, "Impact Summary")
        impact = report.get("impact_summary") or {}
        add_kv(pdf, "Critical/High", _fmt_number(posture.get("critical_high_count")))
        add_kv(pdf, "KEV Cases", _fmt_number(posture.get("kev_count")))
        add_kv(pdf, "Confirmed Reachable", _fmt_number(posture.get("reachable_count")))
        impact_text = impact_section_text or _safe_text(impact.get("impact_note") or "No evidence provided.")
        if _normalized_text_signature(impact_text) != _normalized_text_signature(executive_text):
            add_paragraph(pdf, impact_text, line_height=6, indent=2.0)

        add_block_title(pdf, "Current Action Snapshot")
        current_action_snapshot = report.get("current_action_snapshot") or {}
        add_kv(pdf, "Fix Now", _fmt_number(current_action_snapshot.get("fix_now_count")))
        add_kv(pdf, "Plan Remediation", _fmt_number(current_action_snapshot.get("plan_remediation_count")))
        add_kv(pdf, "Mitigate", _fmt_number(current_action_snapshot.get("mitigate_count")))
        add_kv(pdf, "Monitor", _fmt_number(current_action_snapshot.get("monitor_count")))
        add_kv(pdf, "Fix Available", _fmt_number(current_action_snapshot.get("fix_available_count")))
        add_kv(pdf, "Reachable/Likely", _fmt_number(current_action_snapshot.get("reachable_or_likely_count")))

        add_block_title(pdf, "Recommended Management Actions")
        management_signature = _normalized_text_signature(management_text)
        narrative_signatures = {
            _normalized_text_signature(executive_text),
            _normalized_text_signature(impact_text),
        }
        if management_text and management_signature not in narrative_signatures:
            add_paragraph(pdf, management_text, line_height=6, indent=2.0)
        management_actions = _dedupe_records(
            [dict(item) for item in (report.get("recommended_management_actions") or [])],
            lambda item: (
                f"{str(item.get('action') or '').strip().lower()}|"
                f"{str(item.get('owner_type') or '').strip().lower()}|"
                f"{str(item.get('urgency') or '').strip().lower()}"
            ),
        )
        for item in management_actions[:5]:
            add_paragraph(
                pdf,
                f"- {item.get('action') or 'No action provided.'} [{item.get('owner_type') or 'owner pending'} | {item.get('urgency') or 'monitor'}]",
                line_height=6,
                indent=2.0,
            )

        add_block_title(pdf, "Next Verification Checkpoint")
        checkpoint = report.get("next_verification_checkpoint") or {}
        add_kv(pdf, "Trigger", checkpoint.get("trigger") or "No evidence provided.")
        add_kv(pdf, "Goal", checkpoint.get("goal") or "No evidence provided.")
        add_paragraph(pdf, checkpoint.get("note") or "No evidence provided.", line_height=6, indent=2.0)

    return _build_pdf("Stakeholder Security Summary", project, generated_at, _render_blocks)


def export_developer_report_pdf(report: DeveloperReport) -> bytes:
    """
    Export one developer report object to a lightweight PDF payload.
    """

    project = _safe_text(report.get("project", "unknown-project"))
    generated_at = _safe_text(report.get("generated_at", "unknown-time"))

    def _render_blocks(pdf: Any, add_block_title: Any, add_kv: Any, add_paragraph: Any) -> None:
        if report.get("run_id"):
            add_paragraph(pdf, f"Run ID: {report.get('run_id')}", line_height=6.5, indent=2.0)
        if report.get("scan_id"):
            add_paragraph(pdf, f"Scan ID: {report.get('scan_id')}", line_height=6.5, indent=2.0)
        if report.get("source_commit"):
            add_paragraph(pdf, f"Source Commit: {report.get('source_commit')}", line_height=6.5, indent=2.0)

        triage = report.get("triage_summary") or {}
        triage_text = _markdown_to_plain_text(
            _extract_markdown_section(report.get("narrative"), "Triage Overview")
        )
        triage_signature = _normalized_text_signature(triage_text)
        if triage_text:
            add_block_title(pdf, "Triage Overview")
            add_paragraph(pdf, triage_text, line_height=6, indent=2.0)
        add_kv(pdf, "Total Cases", _fmt_number(triage.get("total_cases")))
        add_kv(pdf, "Fix Now", _fmt_number(triage.get("fix_now_count")))
        add_kv(pdf, "Plan Remediation", _fmt_number(triage.get("plan_remediation_count")))
        add_kv(pdf, "Mitigate", _fmt_number(triage.get("mitigate_count")))
        add_kv(pdf, "Monitor", _fmt_number(triage.get("monitor_count")))
        add_kv(pdf, "Confirmed Reachable", _fmt_number(triage.get("confirmed_count")))
        add_kv(pdf, "Likely Reachable", _fmt_number(triage.get("likely_count")))
        add_kv(pdf, "Likely Unreachable", _fmt_number(triage.get("unlikely_count")))
        add_kv(pdf, "No Sink Data", _fmt_number(triage.get("no_sink_data_count")))

        add_block_title(pdf, "Immediate Fix Queue")
        fix_rationale = _markdown_to_plain_text(
            _extract_markdown_section(report.get("narrative"), "Immediate Fix Rationale")
        )
        if fix_rationale and _normalized_text_signature(fix_rationale) != triage_signature:
            add_paragraph(pdf, fix_rationale, line_height=6, indent=2.0)

        findings = _dedupe_records(
            [dict(item) for item in (report.get("detailed_technical_findings") or [])],
            lambda item: (
                f"{str(item.get('vuln_id') or '').strip().lower()}|"
                f"{str(item.get('component') or '').strip().lower()}"
            ),
        )
        finding_lookup = {
            (
                f"{str(item.get('vuln_id') or '').strip().lower()}|"
                f"{str(item.get('component') or '').strip().lower()}"
            ): item
            for item in findings
        }

        immediate_fix_queue = _dedupe_records(
            [dict(item) for item in (report.get("immediate_fix_queue") or [])],
            lambda item: (
                f"{str(item.get('vuln_id') or '').strip().lower()}|"
                f"{str(item.get('component') or '').strip().lower()}|"
                f"{str(item.get('target_version') or '').strip().lower()}"
            ),
        )
        if not immediate_fix_queue:
            add_paragraph(pdf, "No immediate fix queue entries available.", line_height=6, indent=2.0)
        else:
            for item in immediate_fix_queue[:5]:
                lookup_key = (
                    f"{str(item.get('vuln_id') or '').strip().lower()}|"
                    f"{str(item.get('component') or '').strip().lower()}"
                )
                finding = finding_lookup.get(lookup_key, {})
                if item.get("production_evidence") and item.get("test_only_evidence"):
                    evidence_scope = "mixed"
                elif item.get("production_evidence"):
                    evidence_scope = "production"
                elif item.get("test_only_evidence"):
                    evidence_scope = "test-only"
                else:
                    evidence_scope = "unclassified"
                add_paragraph(
                    pdf,
                    (
                        f"- {item.get('vuln_id', 'N/A')} | {item.get('component', 'N/A')} "
                        f"{item.get('current_version') or 'unknown'} -> {item.get('target_version') or 'investigate'} "
                        f"| {item.get('reachability_verdict', 'N/A')} | severity={finding.get('severity') or item.get('severity') or 'N/A'} "
                        f"| cvss={_fmt_decimal(finding.get('cvss') or item.get('cvss'))} "
                        f"| risk={_fmt_decimal(finding.get('risk_score') or item.get('risk_score'), digits=2)} "
                        f"| confidence={item.get('evidence_confidence', 'N/A')} | evidence={evidence_scope}"
                    ),
                    line_height=6,
                    indent=2.0,
                )
                call_locations = (finding.get("call_locations") or item.get("key_call_locations") or [])[:5]
                if call_locations:
                    add_paragraph(
                        pdf,
                        f"Call evidence: {', '.join(call_locations)}",
                        line_height=6,
                        indent=4.0,
                    )
                nvd_url = str(finding.get("nvd_url") or item.get("nvd_url") or "").strip()
                if nvd_url:
                    add_paragraph(pdf, f"NVD: {nvd_url}", line_height=6, indent=4.0)
                cve_description = str(
                    finding.get("cve_description")
                    or item.get("cve_description")
                    or finding.get("advisory_summary")
                    or ""
                ).strip()
                if cve_description:
                    add_paragraph(pdf, f"CVE summary: {cve_description}", line_height=6, indent=4.0)
                if finding.get("sink_functions"):
                    add_paragraph(
                        pdf,
                        f"Sinks: {', '.join((finding.get('sink_functions') or [])[:3])}",
                        line_height=6,
                        indent=4.0,
                    )
                add_paragraph(pdf, f"Why fix now: {item.get('why_fix_now') or 'No evidence provided.'}", line_height=6, indent=4.0)
                add_paragraph(pdf, f"Next action: {item.get('next_action') or 'No evidence provided.'}", line_height=6, indent=4.0)

        monitor_candidates = [
            item
            for item in findings
            if str(item.get("decision_tier") or "") in {"monitor", "accept_risk", "plan_remediation", "mitigate"}
            and str(item.get("reachability_verdict") or "") in {"no_sink_data", "likely_unreachable"}
        ]
        if monitor_candidates:
            add_block_title(pdf, "Monitor-Tier Highlights")
            add_paragraph(
                pdf,
                f"{len(monitor_candidates)} highlighted case(s) currently remain no_sink_data or likely_unreachable.",
                line_height=6,
                indent=2.0,
            )
            for item in monitor_candidates[:8]:
                targets = ", ".join(item.get("fix_versions") or []) or "N/A"
                add_paragraph(
                    pdf,
                    (
                        f"- {item.get('vuln_id', 'N/A')} | {item.get('component', 'N/A')} "
                        f"{item.get('current_version') or 'unknown'} | "
                        f"severity={item.get('severity', 'N/A')} | cvss={_fmt_decimal(item.get('cvss'))} | "
                        f"reachability={item.get('reachability_verdict', 'N/A')} | "
                        f"depth={item.get('dependency_depth') if item.get('dependency_depth') is not None else 'unknown'} | "
                        f"fix={targets}"
                    ),
                    line_height=6,
                    indent=2.0,
                )

        add_block_title(pdf, "Verification Checklist")
        for item in _dedupe_text_items(report.get("verification_checklist") or [])[:8]:
            add_paragraph(pdf, f"- {item}", line_height=6, indent=2.0)
        verification_delta = report.get("verification_delta") or {}
        baseline_scan = str(verification_delta.get("baseline_scan_id") or "").strip().lower()
        current_scan = str(verification_delta.get("current_scan_id") or "").strip().lower()
        scans_are_present = (
            baseline_scan not in {"", "none", "unknown"}
            and current_scan not in {"", "none", "unknown"}
        )
        if verification_delta_is_meaningful(verification_delta) and scans_are_present:
            add_kv(pdf, "Baseline Scan", verification_delta.get("baseline_scan_id") or "none")
            add_kv(pdf, "Current Scan", verification_delta.get("current_scan_id") or "unknown")
            add_kv(pdf, "Resolved Cases", _fmt_number(verification_delta.get("resolved_cases")))
            add_kv(pdf, "Risk Decreased", _fmt_number(verification_delta.get("risk_decreased_cases")))
            add_kv(pdf, "Verdict Improved", _fmt_number(verification_delta.get("verdict_improved_cases")))
        add_paragraph(pdf, verification_delta.get("note") or "No evidence provided.", line_height=6, indent=2.0)

    return _build_pdf("Developer Remediation Report", project, generated_at, _render_blocks)
