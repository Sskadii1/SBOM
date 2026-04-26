"""
Safe, limited rich-text rendering for PDF-oriented report prose.
"""

from __future__ import annotations

import html
import re


_BULLET_RE = re.compile(r"^\s*[-*]\s+")
_ORDERED_RE = re.compile(r"^\s*\d+\.\s+")
_TABLE_DIVIDER_RE = re.compile(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*|__([^_]+)__")
_ITALIC_RE = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)|(?<!_)_([^_\n]+)_(?!_)")


def _escape_inline(value: str) -> str:
    return html.escape(value, quote=False)


def _render_inline(value: str) -> str:
    placeholders: list[str] = []

    def _store(tag: str, content: str) -> str:
        placeholders.append(f"<{tag}>{content}</{tag}>")
        return f"[[[PH{len(placeholders) - 1}]]]"

    escaped = _escape_inline(value)

    def _code_repl(match: re.Match[str]) -> str:
        return _store("code", _escape_inline(match.group(1).strip()))

    rendered = _INLINE_CODE_RE.sub(_code_repl, escaped)

    def _bold_repl(match: re.Match[str]) -> str:
        content = match.group(1) or match.group(2) or ""
        return _store("strong", _escape_inline(content.strip()))

    rendered = _BOLD_RE.sub(_bold_repl, rendered)

    def _italic_repl(match: re.Match[str]) -> str:
        content = match.group(1) or match.group(2) or ""
        return _store("em", _escape_inline(content.strip()))

    rendered = _ITALIC_RE.sub(_italic_repl, rendered)
    rendered = rendered.replace("\n", "<br>")

    for index, replacement in enumerate(placeholders):
        rendered = rendered.replace(f"[[[PH{index}]]]", replacement)
    return rendered


def _split_blocks(value: str) -> list[str]:
    normalized = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return []
    return [block.strip() for block in re.split(r"\n\s*\n", normalized) if block.strip()]


def _table_cells(line: str) -> list[str]:
    stripped = line.strip().strip("|")
    return [cell.strip() for cell in stripped.split("|")]


def _looks_like_table(lines: list[str]) -> bool:
    return len(lines) >= 2 and "|" in lines[0] and bool(_TABLE_DIVIDER_RE.match(lines[1]))


def _render_table(lines: list[str]) -> str:
    headers = _table_cells(lines[0])
    rows = [_table_cells(line) for line in lines[2:] if line.strip()]
    if not headers:
        return ""

    header_html = "".join(f"<th>{_render_inline(cell)}</th>" for cell in headers)
    body_rows = []
    for row in rows:
        padded = row + [""] * max(len(headers) - len(row), 0)
        body_rows.append(
            "<tr>"
            + "".join(f"<td>{_render_inline(cell)}</td>" for cell in padded[: len(headers)])
            + "</tr>"
        )
    body_html = "".join(body_rows) or (
        "<tr>" + "".join("<td></td>" for _ in headers) + "</tr>"
    )
    return (
        '<div class="prose-table-wrap">'
        '<table class="prose-table">'
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{body_html}</tbody>"
        "</table>"
        "</div>"
    )


def _render_list(lines: list[str], *, ordered: bool) -> str:
    tag = "ol" if ordered else "ul"
    prefix_re = _ORDERED_RE if ordered else _BULLET_RE
    items = []
    for line in lines:
        stripped = prefix_re.sub("", line.strip(), count=1).strip()
        if not stripped:
            continue
        items.append(f"<li>{_render_inline(stripped)}</li>")
    return f"<{tag}>{''.join(items)}</{tag}>" if items else ""


def render_report_rich_text(value: str | None) -> str:
    blocks = _split_blocks(str(value or ""))
    if not blocks:
        return "<p>No evidence provided.</p>"

    rendered_blocks: list[str] = []
    for block in blocks:
        lines = [line.rstrip() for line in block.split("\n") if line.strip()]
        if not lines:
            continue
        if _looks_like_table(lines):
            rendered_blocks.append(_render_table(lines))
            continue
        if all(_BULLET_RE.match(line) for line in lines):
            rendered_blocks.append(_render_list(lines, ordered=False))
            continue
        if all(_ORDERED_RE.match(line) for line in lines):
            rendered_blocks.append(_render_list(lines, ordered=True))
            continue
        rendered_blocks.append(f"<p>{_render_inline(block.strip())}</p>")

    return "".join(rendered_blocks) or "<p>No evidence provided.</p>"
