"""
PDF export helpers for report-driven outputs.
"""

from __future__ import annotations

import re
from typing import Any

from backend.models import StakeholderReport

_REPORT_HEADER_NAMES = {
    "executive security summary",
    "priority actions",
    "impact summary",
    "action buckets",
    "status snapshot",
    "next verification checkpoint",
}


def _safe_text(value: Any) -> str:
    text = str(value) if value is not None else ""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _fmt_number(value: Any) -> str:
    try:
        return str(int(value))
    except Exception:
        return "0"


def _markdown_to_plain_text(value: Any) -> str:
    """
    Convert lightweight Markdown content to plain text for PDF rendering.
    """
    text = str(value) if value is not None else ""
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

    header_pattern = re.compile(
        rf"(?im)^\s*#{1,6}\s*{re.escape(section_title)}\s*$"
    )
    match = header_pattern.search(text)
    if not match:
        return text.strip()

    body_start = match.end()
    remaining = text[body_start:]
    next_header = re.search(r"(?im)^\s*#{1,6}\s+.+$", remaining)
    if next_header:
        return remaining[: next_header.start()].strip()
    return remaining.strip()


def export_stakeholder_report_pdf(report: StakeholderReport) -> bytes:
    """
    Export one stakeholder report object to a lightweight PDF payload.
    """
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
            self.cell(0, 6, _safe_text("Stakeholder Security Summary"), ln=1)
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

    project = _safe_text(report.get("project", "unknown-project"))
    generated_at = _safe_text(report.get("generated_at", "unknown-time"))

    pdf = _PDF()
    pdf.header_project = f"Project: {project}"
    pdf.footer_generated_at = f"Generated: {generated_at}"
    pdf.set_margins(16, 24, 16)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_title(_safe_text(f"Stakeholder Security Summary - {project}"))
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(15, 23, 42)
    add_paragraph(pdf, "Executive Briefing Snapshot", line_height=8)
    pdf.set_font("Helvetica", "", 10)
    add_paragraph(pdf, f"Project: {project}", line_height=6.5, indent=2.0)
    add_paragraph(pdf, f"Generated At: {generated_at}", line_height=6.5, indent=2.0)
    if report.get("run_id"):
        add_paragraph(pdf, f"Run ID: {report.get('run_id')}", line_height=6.5, indent=2.0)

    posture = report.get("posture_summary") or {}
    add_block_title(pdf, "Posture Summary")
    add_kv(pdf, "Total Cases", _fmt_number(posture.get("total_cases")))
    add_kv(pdf, "Critical/High", _fmt_number(posture.get("critical_high_cases")))
    add_kv(pdf, "KEV Cases", _fmt_number(posture.get("kev_cases")))
    add_kv(pdf, "Reachable/Likely", _fmt_number(posture.get("reachable_or_likely_cases")))
    add_kv(pdf, "Fix Available", _fmt_number(posture.get("fix_available_cases")))

    executive_section = _extract_markdown_section(
        report.get("narrative"),
        "Executive Security Summary",
    )
    narrative = _markdown_to_plain_text(executive_section)
    if narrative:
        add_block_title(pdf, "Executive Security Summary")
        add_paragraph(pdf, narrative, line_height=6, indent=2.0)

    top_actions = report.get("top_priority_actions") or []
    add_block_title(pdf, "Top Priority Actions")
    if not top_actions:
        add_paragraph(pdf, "No evidence provided.", line_height=6, indent=2.0)
    else:
        for idx, item in enumerate(top_actions[:12], start=1):
            line = (
                f"{idx}. {item.get('vuln_id', 'N/A')} | {item.get('component_name', 'N/A')} | "
                f"tier={item.get('decision_tier', 'N/A')} | risk={item.get('risk_score', 'N/A')}"
            )
            add_paragraph(pdf, line, line_height=6, indent=2.0)
            add_paragraph(pdf, f"Rationale: {item.get('rationale', 'N/A')}", line_height=6, indent=4.0)
            add_paragraph(
                pdf,
                f"Action: {item.get('recommended_action', 'No guidance provided.')}",
                line_height=6,
                indent=4.0,
            )
            pdf.ln(0.6)

    impact = report.get("impact_summary") or {}
    add_block_title(pdf, "Impact Summary")
    add_kv(pdf, "Runtime Affected", _fmt_number(impact.get("runtime_affected_cases")))
    add_kv(pdf, "Direct Dependency Cases", _fmt_number(impact.get("direct_dependency_cases")))
    add_kv(pdf, "Transitive Dependency Cases", _fmt_number(impact.get("transitive_dependency_cases")))
    add_kv(pdf, "Reachable/Likely", _fmt_number(impact.get("reachable_or_likely_cases")))
    add_paragraph(pdf, impact.get("impact_note") or "No evidence provided.", line_height=6, indent=2.0)

    action_buckets = report.get("action_buckets") or []
    add_block_title(pdf, "Action Buckets")
    if not action_buckets:
        add_paragraph(pdf, "No evidence provided.", line_height=6, indent=2.0)
    else:
        for idx, bucket in enumerate(action_buckets, start=1):
            related = bucket.get("related_vuln_ids") or []
            related_text = ", ".join(str(v) for v in related[:8]) if related else "N/A"
            line = (
                f"{idx}. tier={bucket.get('decision_tier', 'N/A')} | "
                f"cases={bucket.get('case_count', 0)}"
            )
            add_paragraph(pdf, line, line_height=6, indent=2.0)
            add_paragraph(pdf, f"Rationale: {bucket.get('rationale', 'N/A')}", line_height=6, indent=4.0)
            add_paragraph(
                pdf,
                f"Action: {bucket.get('recommended_action', 'No guidance provided.')}",
                line_height=6,
                indent=4.0,
            )
            add_paragraph(pdf, f"CVEs: {related_text}", line_height=6, indent=4.0)
            pdf.ln(0.6)

    add_block_title(pdf, "Tier Action Guidance")
    if not action_buckets:
        add_paragraph(pdf, "No evidence provided.", line_height=6, indent=2.0)
    else:
        for bucket in action_buckets:
            line = (
                f"- {bucket.get('decision_tier', 'N/A')}: "
                f"{bucket.get('recommended_action', 'No guidance provided.')}"
            )
            add_paragraph(pdf, line, line_height=6, indent=2.0)

    status_snapshot = report.get("status_snapshot") or {}
    add_block_title(pdf, "Status Snapshot")
    add_kv(pdf, "New", _fmt_number(status_snapshot.get("new")))
    add_kv(pdf, "Under Review", _fmt_number(status_snapshot.get("under_review")))
    add_kv(pdf, "Planned", _fmt_number(status_snapshot.get("planned")))
    add_kv(pdf, "In Progress", _fmt_number(status_snapshot.get("in_progress")))
    add_kv(pdf, "Mitigated", _fmt_number(status_snapshot.get("mitigated")))
    add_kv(pdf, "Resolved Pending Verify", _fmt_number(status_snapshot.get("resolved_pending_verify")))
    add_kv(pdf, "Verified Closed", _fmt_number(status_snapshot.get("verified_closed")))

    checkpoint = report.get("next_verification_checkpoint") or {}
    add_block_title(pdf, "Next Verification Checkpoint")
    add_paragraph(pdf, checkpoint.get("guidance") or "No evidence provided.", line_height=6, indent=2.0)
    for trigger in checkpoint.get("trigger_conditions") or []:
        add_paragraph(pdf, f"- {trigger}", line_height=6, indent=2.0)

    try:
        payload = pdf.output(dest="S")
    except TypeError:
        # fpdf2 newer signatures may not accept dest; default output returns bytes/bytearray.
        payload = pdf.output()

    if isinstance(payload, str):
        return payload.encode("latin-1", errors="replace")
    if isinstance(payload, bytearray):
        return bytes(payload)
    return bytes(payload)
