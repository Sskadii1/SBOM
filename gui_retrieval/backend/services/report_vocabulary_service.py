"""
Presentation vocabulary for audience-facing report language.
"""

from __future__ import annotations

import re
from typing import Literal

Audience = Literal["stakeholder", "developer"]
VocabularyStyle = Literal["badge", "sentence"]

_REACHABILITY_VOCAB: dict[Audience, dict[str, dict[VocabularyStyle, str]]] = {
    "stakeholder": {
        "confirmed_reachable": {
            "badge": "Direct evidence of use",
            "sentence": "has direct code-level evidence of use in the application",
        },
        "likely_reachable": {
            "badge": "Signs of active use",
            "sentence": "shows signs of use in relevant application paths",
        },
        "likely_unreachable": {
            "badge": "Not observed as directly used",
            "sentence": "was not observed as directly used in the current scan",
        },
        "no_sink_data": {
            "badge": "Evidence still incomplete",
            "sentence": "does not yet have enough sink-level evidence to judge practical exposure",
        },
        "unknown": {
            "badge": "Evidence pending",
            "sentence": "still needs additional evidence before practical exposure can be judged",
        },
    },
    "developer": {
        "confirmed_reachable": {
            "badge": "Direct call evidence",
            "sentence": "has direct call evidence in project code",
        },
        "likely_reachable": {
            "badge": "Import/use evidence",
            "sentence": "has import or usage evidence, but no direct vulnerable sink call was confirmed",
        },
        "likely_unreachable": {
            "badge": "No direct use observed",
            "sentence": "was scanned successfully and no direct or import evidence supporting active use was found",
        },
        "no_sink_data": {
            "badge": "Sink evidence missing",
            "sentence": "does not have sink-level evidence yet, so practical reachability cannot be concluded",
        },
        "unknown": {
            "badge": "Evidence pending",
            "sentence": "still needs more evidence before practical reachability can be concluded",
        },
    },
}

_DECISION_TIER_VOCAB: dict[Audience, dict[str, dict[VocabularyStyle, str]]] = {
    "stakeholder": {
        "fix_now": {
            "badge": "Act in current release",
            "sentence": "needs action in the current release window",
        },
        "plan_remediation": {
            "badge": "Schedule next release",
            "sentence": "should be scheduled into the next remediation window",
        },
        "mitigate": {
            "badge": "Mitigate and assign",
            "sentence": "needs mitigation ownership or a compensating control decision",
        },
        "monitor": {
            "badge": "Keep under observation",
            "sentence": "should stay under observation until stronger evidence or a release window is available",
        },
        "accept_risk": {
            "badge": "Track accepted risk",
            "sentence": "is currently being tracked as accepted risk and should still be revisited at the next checkpoint",
        },
    },
    "developer": {
        "fix_now": {
            "badge": "Immediate queue",
            "sentence": "belongs in the immediate remediation queue",
        },
        "plan_remediation": {
            "badge": "Planned upgrade",
            "sentence": "belongs in the planned upgrade queue",
        },
        "mitigate": {
            "badge": "Mitigation / investigation",
            "sentence": "needs mitigation work or deeper investigation before an upgrade can be closed out",
        },
        "monitor": {
            "badge": "Monitor",
            "sentence": "should remain in the monitor queue pending stronger evidence or a later window",
        },
        "accept_risk": {
            "badge": "Accepted risk",
            "sentence": "is being tracked as accepted risk and should still be revisited when evidence changes",
        },
    },
}

_EVIDENCE_SCOPE_VOCAB: dict[Audience, dict[str, str]] = {
    "stakeholder": {
        "production": "Production path evidence",
        "test-only": "Test-only evidence",
        "mixed": "Mixed production and test evidence",
        "unknown": "Scope not yet classified",
    },
    "developer": {
        "production": "Production code path",
        "test-only": "Test-only path",
        "mixed": "Mixed production and test paths",
        "unknown": "Unclassified scope",
    },
}

_URGENCY_LABELS = {
    "immediate": "Immediate",
    "next_window": "Next release window",
    "monitor": "Monitor",
}


def _normalize_key(value: str | None, *, fallback: str = "unknown") -> str:
    text = str(value or "").strip().lower()
    return text or fallback


def _lookup_vocab(
    mapping: dict[Audience, dict[str, dict[VocabularyStyle, str]]],
    audience: Audience,
    key: str | None,
) -> dict[VocabularyStyle, str]:
    normalized = _normalize_key(key)
    audience_mapping = mapping[audience]
    return audience_mapping.get(normalized, audience_mapping["unknown"])


def present_reachability(
    reachability_verdict: str | None,
    audience: Audience,
    *,
    style: VocabularyStyle = "badge",
) -> str:
    return _lookup_vocab(_REACHABILITY_VOCAB, audience, reachability_verdict)[style]


def present_decision_tier(
    decision_tier: str | None,
    audience: Audience,
    *,
    style: VocabularyStyle = "badge",
) -> str:
    normalized = _normalize_key(decision_tier, fallback="monitor")
    audience_mapping = _DECISION_TIER_VOCAB[audience]
    return audience_mapping.get(normalized, audience_mapping["monitor"])[style]


def present_evidence_scope(scope: str | None, audience: Audience) -> str:
    normalized = _normalize_key(scope)
    audience_mapping = _EVIDENCE_SCOPE_VOCAB[audience]
    return audience_mapping.get(normalized, audience_mapping["unknown"])


def present_urgency(urgency: str | None) -> str:
    normalized = _normalize_key(urgency, fallback="monitor")
    return _URGENCY_LABELS.get(normalized, _URGENCY_LABELS["monitor"])


def reachability_legend(audience: Audience) -> dict[str, str]:
    return {
        key: values["sentence"]
        for key, values in _REACHABILITY_VOCAB[audience].items()
        if key != "unknown"
    }


def decision_tier_legend(audience: Audience) -> dict[str, str]:
    return {
        key: values["sentence"]
        for key, values in _DECISION_TIER_VOCAB[audience].items()
    }


def normalize_labeled_text(label: str, text: str | None) -> str:
    """
    Prevent duplicated prefixes such as "Why now: Why now: ...".
    """
    cleaned = str(text or "").strip()
    if not cleaned:
        return ""
    normalized_label = re.escape(str(label or "").strip().rstrip(":"))
    if not normalized_label:
        return cleaned
    return re.sub(
        rf"^(?:{normalized_label}\s*:\s*)+",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).strip()
