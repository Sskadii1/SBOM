"""
Canonical lifecycle statuses for vulnerability alert cases.
"""

from __future__ import annotations

from typing import Literal, cast

CaseStatus = Literal[
    "new",
    "under_review",
    "planned",
    "in_progress",
    "mitigated",
    "resolved_pending_verify",
    "verified_closed",
]

VALID_CASE_STATUSES: list[CaseStatus] = [
    "new",
    "under_review",
    "planned",
    "in_progress",
    "mitigated",
    "resolved_pending_verify",
    "verified_closed",
]

DEFAULT_CASE_STATUS: CaseStatus = "new"

_LEGACY_STATUS_MAP: dict[str, CaseStatus] = {
    "fix_planned": "planned",
    "mitigation_planned": "planned",
    "deferred": "planned",
    "accepted_risk": "planned",
}


def is_valid_case_status(value: str | None) -> bool:
    """Return True when ``value`` is one of the canonical case statuses."""
    return bool(value) and value in VALID_CASE_STATUSES


def normalize_case_status(
    value: str | None,
    *,
    default: CaseStatus = DEFAULT_CASE_STATUS,
) -> CaseStatus:
    """
    Normalize free-form input into a canonical case status.

    Unknown values fall back to ``default`` for backward compatibility with
    legacy records.
    """
    raw = (value or "").strip()
    if is_valid_case_status(raw):
        return cast(CaseStatus, raw)
    mapped = _LEGACY_STATUS_MAP.get(raw)
    if mapped:
        return mapped
    return default
