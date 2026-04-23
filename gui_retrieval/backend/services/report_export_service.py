"""
Structured PDF export helpers for report-driven outputs.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from backend.models import DeveloperReport, StakeholderReport
from backend.services.report_rendering_service import (
    render_developer_report_html,
    render_stakeholder_report_html,
)

_KNOWN_BROWSER_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge",
)


def _dedupe_text_items(values: list[Any]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = " ".join(str(value or "").split()).strip()
        if not text:
            continue
        signature = text.lower()
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(text)
    return unique


def _workspace_temp_root() -> Path:
    root = Path(__file__).resolve().parents[3] / ".report_export_tmp"
    root.mkdir(exist_ok=True)
    return root


def _find_headless_browser() -> str | None:
    for path in _KNOWN_BROWSER_PATHS:
        if Path(path).exists():
            return path
    for candidate in ("chrome", "msedge", "chromium", "brave"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _render_pdf_with_weasyprint(html: str) -> bytes | None:
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError(f"WeasyPrint is unavailable: {type(exc).__name__}: {exc}") from exc
    try:
        return HTML(string=html).write_pdf()
    except Exception as exc:
        raise RuntimeError(f"WeasyPrint failed to render PDF: {type(exc).__name__}: {exc}") from exc


def _run_browser_print(browser_path: str, html_path: Path, pdf_path: Path, *, headless_flag: str) -> None:
    command = [
        browser_path,
        headless_flag,
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--run-all-compositor-stages-before-draw",
        "--allow-file-access-from-files",
        f"--print-to-pdf={pdf_path}",
        "--no-pdf-header-footer",
        html_path.as_uri(),
    ]
    if Path(browser_path).anchor == "/":
        command.insert(2, "--no-sandbox")
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _render_pdf_with_browser(html: str) -> bytes:
    browser_path = _find_headless_browser()
    if not browser_path:
        raise RuntimeError(
            "PDF export requires a supported headless browser (Chrome or Edge) or WeasyPrint."
        )

    temp_root = _workspace_temp_root() / f"render-{uuid.uuid4().hex}"
    temp_root.mkdir(parents=True, exist_ok=True)
    try:
        html_path = temp_root / "report.html"
        pdf_path = temp_root / "report.pdf"
        html_path.write_text(html, encoding="utf-8")

        last_error: Exception | None = None
        for headless_flag in ("--headless=new", "--headless"):
            try:
                _run_browser_print(browser_path, html_path, pdf_path, headless_flag=headless_flag)
                if pdf_path.exists():
                    return pdf_path.read_bytes()
            except Exception as exc:  # pragma: no cover - exercised conditionally by local browser version
                last_error = exc

        raise RuntimeError("Headless browser PDF rendering failed.") from last_error
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _render_pdf_from_html(html: str) -> bytes:
    weasyprint_error: RuntimeError | None = None
    try:
        return _render_pdf_with_weasyprint(html)
    except RuntimeError as exc:
        weasyprint_error = exc

    try:
        return _render_pdf_with_browser(html)
    except RuntimeError as browser_error:
        if weasyprint_error is not None:
            raise RuntimeError(
                f"{browser_error} Primary WeasyPrint path also failed: {weasyprint_error}"
            ) from weasyprint_error
        raise


def export_stakeholder_report_pdf(report: StakeholderReport) -> bytes:
    return _render_pdf_from_html(render_stakeholder_report_html(report))


def export_developer_report_pdf(report: DeveloperReport) -> bytes:
    return _render_pdf_from_html(render_developer_report_html(report))


def export_stakeholder_report_pdf_for_project(
    project_name: str,
    *,
    scan_id: str | None = None,
) -> bytes:
    from backend.services.report_service import generate_stakeholder_report

    report = generate_stakeholder_report(project_name, scan_id=scan_id, use_llm=True)
    return export_stakeholder_report_pdf(report)


def export_developer_report_pdf_for_project(
    project_name: str,
    *,
    scan_id: str | None = None,
    vuln_id: str | None = None,
    component_id: str | None = None,
) -> bytes:
    from backend.services.report_service import generate_developer_report

    report = generate_developer_report(
        project_name,
        vuln_id=vuln_id,
        component_id=component_id,
        scan_id=scan_id,
        use_llm=True,
    )
    return export_developer_report_pdf(report)
