"""
Shared helpers for report presentation decisions.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

_NUMERIC_VERSION_PATTERN = re.compile(r"^[vV]?(\d+(?:\.\d+)*)(?:[-+]?([0-9A-Za-z.-]+))?$")
_TOKEN_PATTERN = re.compile(r"\d+|[A-Za-z]+")
_TIER_ORDER = {
    "fix_now": 0,
    "plan_remediation": 1,
    "mitigate": 2,
    "monitor": 3,
    "accept_risk": 4,
}
_VERDICT_ORDER = {
    "confirmed_reachable": 0,
    "likely_reachable": 1,
    "no_sink_data": 2,
    "likely_unreachable": 3,
    "unknown": 4,
}
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}
_LOW_VALUE_SUMMARIES = {
    "no evidence provided.",
    "no project-specific impact summary is currently available.",
    "impact summary is not available yet.",
    "advisory summary.",
    "sample note",
}
_MARKDOWN_TABLE_DIVIDER_RE = re.compile(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$")


def _tokenize_text(value: str) -> tuple[tuple[int, int | str], ...]:
    tokens: list[tuple[int, int | str]] = []
    for item in _TOKEN_PATTERN.findall(value):
        if item.isdigit():
            tokens.append((0, int(item)))
        else:
            tokens.append((1, item.lower()))
    return tuple(tokens)


def _version_sort_key(value: str) -> tuple[int, tuple[int, ...], int, tuple[tuple[int, int | str], ...], str]:
    text = value.strip()
    match = _NUMERIC_VERSION_PATTERN.match(text)
    if not match:
        return (0, tuple(), 0, _tokenize_text(text), text.lower())

    numeric_parts = tuple(int(part) for part in match.group(1).split("."))
    prerelease = match.group(2) or ""
    stable_rank = 1 if not prerelease else 0
    return (
        1,
        numeric_parts,
        stable_rank,
        _tokenize_text(prerelease),
        text.lower(),
    )


def select_preferred_fix_version(fix_versions: list[str] | None) -> str | None:
    """
    Prefer the highest stable-looking fix version instead of trusting source order.
    """
    versions = [str(item).strip() for item in (fix_versions or []) if str(item).strip()]
    if not versions:
        return None
    unique_versions = list(dict.fromkeys(versions))
    return sorted(unique_versions, key=_version_sort_key, reverse=True)[0]


def compact_text(
    value: Any,
    *,
    fallback: str = "",
    max_length: int | None = None,
) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return fallback
    if text.lower() in _LOW_VALUE_SUMMARIES:
        return fallback
    if max_length is None or len(text) <= max_length:
        return text

    trimmed = text[: max_length - 1].rstrip(" ,;:")
    last_break = max(trimmed.rfind(". "), trimmed.rfind("; "), trimmed.rfind(", "))
    if last_break >= max_length // 2:
        trimmed = trimmed[: last_break].rstrip(" ,;:.")
    return f"{trimmed}..."


def unique_text_items(values: list[Any] | None, *, limit: int | None = None) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = " ".join(str(value or "").split()).strip()
        if not text:
            continue
        signature = text.lower()
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(text)
        if limit is not None and len(unique) >= limit:
            break
    return unique


def format_version_path(current_version: Any, target_version: Any, *, fallback: str = "Target pending") -> str:
    current = compact_text(current_version, fallback="unknown")
    target = compact_text(target_version, fallback=fallback)
    return f"{current} -> {target}"


def plain_text_from_markdown(value: Any, *, fallback: str = "") -> str:
    lines: list[str] = []
    for raw_line in str(value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line or _MARKDOWN_TABLE_DIVIDER_RE.match(line):
            continue
        line = re.sub(r"^\s*[-*]\s+", "", line)
        line = re.sub(r"^\s*\d+\.\s+", "", line)
        line = line.replace("`", "").replace("**", "").replace("__", "")
        if line.startswith("|") and line.endswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|") if cell.strip()]
            line = "; ".join(cells)
        lines.append(line)
    return compact_text(" ".join(lines), fallback=fallback)


def verification_delta_has_baseline(verification_delta: Mapping[str, Any] | None) -> bool:
    if not verification_delta:
        return False
    return bool(str(verification_delta.get("baseline_scan_id") or "").strip())


def verification_delta_is_meaningful(verification_delta: Mapping[str, Any] | None) -> bool:
    if not verification_delta_has_baseline(verification_delta):
        return False
    return any(
        int(verification_delta.get(key) or 0) > 0
        for key in ("resolved_cases", "risk_decreased_cases", "verdict_improved_cases")
    )


def compact_findings_for_display(findings: list[Mapping[str, Any]], *, limit: int = 6) -> list[Mapping[str, Any]]:
    """
    Keep the most actionable findings first so exports do not give monitor-tier items
    the same visual weight as immediate queue work.
    """
    ranked = sorted(
        findings,
        key=lambda item: (
            _TIER_ORDER.get(str(item.get("decision_tier") or "monitor"), 9),
            _VERDICT_ORDER.get(str(item.get("reachability_verdict") or "unknown"), 9),
            _SEVERITY_ORDER.get(str(item.get("severity") or "low").lower(), 9),
            -float(item.get("dependency_depth") or 0),
            str(item.get("vuln_id") or ""),
            str(item.get("component") or item.get("component_name") or ""),
        ),
    )
    return ranked[:limit]
