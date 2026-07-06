"""
backend/services/llm_service.py - LLM Explanation Engine.

Uses Anthropic or OpenRouter chat completions.
"""

from __future__ import annotations

from typing import Any
import json
import logging
import re
import textwrap

import requests
import backend.config as config
import backend.services.prompt_service as pf
from backend.services.semgrep_context_service import enrich_evidence_with_semgrep
from backend.services.report_vocabulary_service import (
    present_decision_tier,
    present_evidence_scope,
    present_reachability,
)

logger = logging.getLogger(__name__)

_CLAUDE_PROMPT_CACHE_MIN_CHARS = 1200


_SYSTEM_INSTRUCTION = """\
You are an expert DevSecOps AI assistant analyzing an SBOM vulnerability graph.
You have access to structured evidence extracted from a Neo4j knowledge graph.

CRITICAL RULES:
1. ONLY use the provided evidence. DO NOT hallucinate vulnerabilities, packages, or fix versions.
2. If evidence for a specific claim is missing, explicitly state "No evidence provided."
3. Format output in clean Markdown.
4. Keep explanations concise, professional, and actionable.
5. If asked about CVSS or EPSS, rely EXCLUSIVELY on the provided metrics. Do not supply your own scores.
6. Assess confidence based on the DIRECTNESS of the evidence:
   High (direct path from project to target),
   Medium (long dependency chain or missing fix info),
   Low (most fields N/A or evidence empty).
7. If Semgrep reachability evidence is present, prioritize it when deciding exploitability.
8. Do NOT reveal chain-of-thought, internal reasoning, or meta commentary.
9. Use clean Markdown with plain readable English. Avoid decorative Unicode and avoid corrupted-looking output.
10. If the requested format cannot be satisfied fully, keep the required section headers and write "No evidence provided." where needed."""


_EXPECTED_SECTION_MARKERS: dict[str, list[str]] = {
    "dev_explain": [
        "### Exploitability Verdict",
        "**Verdict:**",
    ],
    "explainability_mode": [
        "**Path Claim**",
        "Path Claim",
    ],
    "multi_audience": [
        "### For the Executive",
        "## For the Executive",
        "# For the Executive",
        "For the Executive",
    ],
    "project_overview": [
        "**Posture Snapshot**",
        "Posture Snapshot",
    ],
    "arch_impact": [
        "**Blast Radius Verdict**",
        "Blast Radius Verdict",
    ],
}

_LEAK_PATTERNS = [
    r"^\s*we need to\b.*$",
    r"^\s*we must\b.*$",
    r"^\s*let'?s\b.*$",
    r"^\s*i need to\b.*$",
    r"^\s*the user\b.*$",
    r"^\s*output format\b.*$",
    r"^\s*\d+\.\s+path claim\b.*$",
    r"^\s*\d+\.\s+evidence correlation\b.*$",
    r"^\s*\d+\.\s+conflict check\b.*$",
    r"^\s*\d+\.\s+confidence\b.*$",
]

_MULTI_AUDIENCE_META_PATTERNS = [
    r"\blet me check\b",
    r"\bactually\b",
    r"\bthis seems inconsistent\b",
    r"\bwait,\s*we have\b",
    r"\blooking:\s*$",
    r"\blooking at the list\b",
    r"\bthe evidence says\b",
    r"\bthis implies\b",
    r"\bit'?s possible that\b",
    r"\bfor the executive,\s*for the security engineer,\s*for the developer\.?\s*$",
    r"\bhowever,\s*note that\b",
    r"\bbut note\b",
    r"\bwe are to\b",
    r"\bfor the table\b",
    r"^columns\s*:",
    r"\bthe requirement says\b",
    r"\bwe'?ll list each unique vulnerability\b",
]

_MULTI_AUDIENCE_META_CLAUSE_MARKERS = [
    " However, note that ",
    " However, ",
    " But note: ",
    " But note ",
    " Actually, ",
    " Let me check",
    " Looking at the list",
    " Looking:",
]

_STAKEHOLDER_REPORT_HEADERS = [
    "What Needs Attention Now",
    "Why It Matters Now",
    "What Action Or Approval Is Needed Next",
    "What Remains Under Observation",
]

_DEVELOPER_REPORT_HEADERS = [
    "Queue Overview",
    "Strongest Evidence",
    "Immediate Next Steps",
    "Verification Guidance",
    "What Is Still Uncertain Or Deferred",
]

_REPORT_LEAK_CUTOFF_MARKERS = [
    "rules:",
    "writing style:",
    "allowed evidence:",
    "forbidden behavior:",
    "output schema:",
    "let's break down",
    "let me check",
    "the instructions say",
    "return markdown with exactly these sections",
    "report json:",
]

_REPORT_PROMPT_ECHO_LINE_PATTERNS = [
    r"^\s*use only facts from the provided report json\.?\s*$",
    r"^\s*prefer concrete remediation language tied to decision tiers and reachability\.?\s*$",
    r"^\s*do not invent package names,\s*cves,\s*commands,\s*or fix versions\.?\s*$",
    r"^\s*if data is missing,\s*say\s+\"?no evidence provided\.?\"?\s*$",
]


def _prompt_dev_explain(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_dev_explain(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Developer Explanation
        -------------------------------
        Explain this vulnerability using evidence-first reasoning.

        EVIDENCE:
        {ev_text}

        IMPORTANT REASONING RULES:
        1) Prioritize evidence in this order:
           Semgrep reachability facts > dependency/location facts > risk metrics.
        2) Do not claim "reachable" unless Semgrep facts support it.
        3) If Semgrep verdict is likely_unreachable and no call locations exist,
           conclude "not confirmed reachable" (not "safe").
        4) If data conflicts, explicitly state the conflict and which evidence was prioritized.
        5) Prefer polished Markdown that reads like a security review note, not a chat reply.
        6) Do not repeat the prompt instructions, do not explain your reasoning process,
           and do not include meta phrases like "based on the prompt", "let me", or "I will".

        OUTPUT FORMAT (exactly these sections):
        ### Exploitability Verdict
        - Start with one bold verdict line: `**Verdict:** Reachable / Not confirmed reachable / Unknown`.
        - Add one short sentence explaining why that verdict was chosen.

        ### Evidence Trace
        - Use a Markdown table with these columns exactly:
          `Signal | Value | Why it matters`
        - Include rows for:
          file:line, dependency depth, semgrep verdict, sink functions, call locations, fix version, advisory impact, public poc.

        ### Technical Reasoning
        - Write 2 to 4 bullet points.
        - Explain how the verdict follows from the evidence.
        - Mention any missing, weak, or conflicting evidence explicitly.
        - Keep each bullet concrete and evidence-linked.

        ### Public POC Status
        - Start with one bold label:
          `**POC:** Present in evidence / Not present in evidence / Unknown`
        - Add one sentence explaining whether a proof-of-concept or exploit reference is present in the provided evidence.
        - If the evidence includes a POC snippet, include one fenced code block with the most relevant excerpt from the evidence only.
        - Do not invent GitHub links, exploit URLs, or public exploit claims if they are not in evidence.

        ### Project Exposure
        - Explain how this project would have to use the vulnerable package for the advisory POC to apply.
        - If project code snippets or Semgrep call locations are present, cite them directly and explain why they are risky.
        - If no project code usage is visible, say that clearly.
        - Focus on the current repository, not a generic package-level explanation.

        ### Impact Summary
        - Write 1 short paragraph in plain English for developers.
        - This section must come AFTER `Public POC Status` and `Project Exposure`.
        - State what can happen if the vulnerable code path is actually reachable in this project.
        - If the advisory text describes RCE, injection, DoS, auth bypass, or data exposure, name that impact explicitly.
        - If the impact is only described in advisory text but not confirmed in this codebase, say that clearly.

        ### Remediation Plan
        - Use 2 parts:
          `Recommended target version:` one line
          `Upgrade action:` one fenced bash code block with the most direct package-manager command if the ecosystem is obvious.
        - If multiple fix versions exist, recommend the safest/highest stable version visible in the evidence.
        - If no fix is available, provide temporary mitigation actions as bullets.

        ### Confidence
        - One bold label on its own line: `**High**`, `**Medium**`, or `**Low**`
        - One sentence justifying the confidence level.

        STYLE RULES:
        - Avoid one-line sections unless evidence is truly missing.
        - Avoid giant paragraphs; prefer short paragraphs, bullets, and one small table.
        - Keep the answer practical and developer-facing.
        - Use plain English only.
        """)


def _prompt_manager_brief(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_manager_brief(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Manager Briefing
        --------------------------
        Provide a high-level executive summary of the riskiest projects based on the provided graph data.

        EVIDENCE (Top Riskiest Projects):
        {ev_text}

        REQUIREMENTS:
        - Which project is at highest risk and why? (Cite total vulnerabilities and KEV hits).
        - What is the aggregated CVSS/EPSS exposure?
        - Recommend immediate resource allocation for remediation.
        - Keep it under 150 words. Focus on business risk.
        """)


def _prompt_triage_queue(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_triage_queue(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Triage Queue Prioritization
        -------------------------------------
        You are filtering alerts for the security operations center (SOC).

        EVIDENCE (High severity, Fix available):
        {ev_text}

        REQUIREMENTS:
        - Prioritize by exploitability evidence first, then KEV, then CVSS.
        - Exploitability evidence priority:
          confirmed_reachable > likely_reachable > no_sink_data > likely_unreachable.
        - If Semgrep data is absent, state that explicitly and downgrade confidence.
        - Output exactly 3 sections:
          1) `Fix Now` (highest operational priority)
          2) `Investigate Next`
          3) `Monitor`
        - For each item include:
          project, CVE, component, semgrep verdict, key evidence, and recommended action.
        """)


def _prompt_explainability(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_explainability(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Graph Path Explainability
        -----------------------------------
        Explain how the project reaches the vulnerable component through the dependency tree.

        EVIDENCE (Dependency Chains):
        {ev_text}

        REQUIREMENTS:
        - This scenario is about provenance and path explanation, not remediation planning.
        - Use this reasoning order:
          Semgrep reachability facts > dependency path facts > risk metrics.
        - In this dataset, `depth=1` means a direct dependency from the project root.
        - Trace the shortest path and explicitly state the depth (hops).
        - If Semgrep and graph-path evidence disagree, report the conflict and explain which evidence is stronger.
        - Do not conclude "reachable" unless Semgrep facts support it.
        - Do not repeat instructions or narrate your thinking process.
        - Output exactly these sections:
          1) `Path Claim`
             Start with `**Claim:** ...`
             Then add one sentence naming the vulnerable component and whether the path is direct or transitive.
          2) `Evidence Correlation`
             Use 3-5 bullets that connect Semgrep evidence, dependency chain, depth, and missing fields.
          3) `Conflict Check`
             State `No material conflict` if signals align; otherwise explain the conflict.
          4) `Confidence`
             Use `**High**`, `**Medium**`, or `**Low**` on one line, then one justification sentence.
        - Do not include remediation commands in this scenario.
        """)


def _prompt_multi_audience(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_multi_audience(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Multi-Audience Dashboard Report
        -----------------------------------------
        Generate a multi-section report targeting different stakeholders.

        EVIDENCE:
        {ev_text}

        REQUIREMENTS:
        - This scenario is the same evidence rewritten for different readers, not three copies of the same paragraph.
        - In this dataset, `depth=1` means a direct dependency from the project root.
        - Every section must reference Semgrep verdict when available.
        - If Semgrep is missing, say "No Semgrep evidence provided."
        - Keep claims scoped to evidence only.
        - Make the three sections meaningfully different in tone and purpose.
        - Do not repeat the same sentence structure across sections.
        - Generate exactly three sections separated by headers:
        ### For the Executive
        (2-3 sentences: business risk, exploitability status, and urgency)

        ### For the Security Engineer
        (Use a Markdown table with these columns exactly:
        `Vulnerability | Severity | Reachability | Dependency Relation | Strongest Evidence`)

        ### For the Developer
        (Use a Markdown table with these columns exactly:
        `Package | Current State | Required Change | Evidence`)
        After the table, provide one fenced bash block if ecosystem is obvious)
        - Keep the Executive section short and non-technical.
        - Keep the Security Engineer section evidence-dense.
        - Keep the Developer section implementation-oriented.
        """)


def _prompt_project_overview(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_project_overview(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Project Posture Overview
        ----------------------------------
        Summarize the overall security health of this single project.

        EVIDENCE:
        {ev_text}

        REQUIREMENTS:
        - Describe the total counts of vulnerabilities and components.
        - If exact Medium / Low counts are not present in evidence, say so explicitly instead of inventing them.
        - Highlight if there are any KEV alerts.
        - If the project has heavy critical exposure, emphasize the need for an audit.
        - Use these sections exactly:
          1) `Posture Snapshot`
          2) `Top Risks`
          3) `Recommended Next Step`
        - In `Top Risks`, use 3 bullets max and cite concrete CVEs/components from the evidence.
        - Do not pad the answer with generic security advice.
        """)


def _prompt_arch_impact(evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    ev_text = pf.format_arch_impact(evidence, summary)
    return textwrap.dedent(f"""\
        SCENARIO: Blast Radius (Architectural Impact)
        ---------------------------------------------
        Explain the potential impact of this vulnerability across the project's dependency graph.

        EVIDENCE:
        {ev_text}

        REQUIREMENTS:
        - This scenario is about blast radius and operational consequence, not a generic vulnerability summary.
        - Identify core vulnerable component and direct/transitive paths.
        - Infer blast radius from BOTH:
          1) graph spread (depth, number of affected paths)
          2) Semgrep exploitability evidence (verdict + call locations).
        - If Semgrep is likely_unreachable with no call locations, treat impact as conditional, not confirmed.
        - Do not repeat instructions or expose chain-of-thought.
        - Output exactly these sections:
          1) `Blast Radius Verdict`
          2) `Supporting Evidence`
             Use a short Markdown table: `Signal | Observation`
          3) `Operational Impact`
          4) `Mitigation Priority`
        - In `Blast Radius Verdict`, state whether impact is confirmed, likely, or conditional.
        - In `Operational Impact`, focus on what part of the project workflow or code path is affected.
        - In `Mitigation Priority`, give a short priority level plus one practical next action.
        """)


_PROMPT_BUILDERS = {
    "dev_explain": _prompt_dev_explain,
    "manager_brief": _prompt_manager_brief,
    "triage_queue": _prompt_triage_queue,
    "explainability_mode": _prompt_explainability,
    "multi_audience": _prompt_multi_audience,
    "project_overview": _prompt_project_overview,
    "arch_impact": _prompt_arch_impact,
}


def get_system_instruction() -> str:
    return _SYSTEM_INSTRUCTION


def build_prompt(scenario_name: str, evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    builder_fn = _PROMPT_BUILDERS.get(scenario_name)
    if not builder_fn:
        raise ValueError(f"No prompt template defined for scenario '{scenario_name}'.")
    return builder_fn(evidence, summary)


def _normalize_claude_prompt_cache_ttl(ttl: str) -> str:
    normalized = str(ttl or "").strip().lower()
    return normalized if normalized in {"5m", "1h"} else "5m"


def _claude_cache_control_payload() -> dict[str, str]:
    """
    Tune TTL with CLAUDE_PROMPT_CACHE_TTL.
    This project treats both cache counters as zero as a non-fatal miss/no-hit signal.
    """
    ttl = _normalize_claude_prompt_cache_ttl(config.CLAUDE_PROMPT_CACHE_TTL)
    if ttl == "1h":
        return {"type": "ephemeral", "ttl": "1h"}
    return {"type": "ephemeral"}


def _should_enable_claude_prompt_cache(stable_prefix_text: str) -> bool:
    if not config.CLAUDE_PROMPT_CACHING_ENABLED:
        return False
    if config.LLM_PROVIDER != "anthropic":
        return False
    return len((stable_prefix_text or "").strip()) >= _CLAUDE_PROMPT_CACHE_MIN_CHARS


def extract_claude_usage_metrics(response_json: dict[str, Any]) -> dict[str, int]:
    usage = response_json.get("usage") or {}
    return {
        "cache_creation_input_tokens": int(usage.get("cache_creation_input_tokens") or 0),
        "cache_read_input_tokens": int(usage.get("cache_read_input_tokens") or 0),
        "input_tokens": int(usage.get("input_tokens") or 0),
        "output_tokens": int(usage.get("output_tokens") or 0),
    }


def compute_total_input_tokens(usage_metrics: dict[str, Any]) -> int:
    return int(usage_metrics.get("cache_read_input_tokens") or 0) + int(
        usage_metrics.get("cache_creation_input_tokens") or 0
    ) + int(usage_metrics.get("input_tokens") or 0)


def _log_claude_usage_metrics(response_json: dict[str, Any], *, purpose: str) -> None:
    usage_metrics = extract_claude_usage_metrics(response_json)
    total_input_tokens = compute_total_input_tokens(usage_metrics)
    cache_hit = usage_metrics["cache_read_input_tokens"] > 0
    cache_miss = (
        usage_metrics["cache_creation_input_tokens"] == 0
        and usage_metrics["cache_read_input_tokens"] == 0
    )
    logger.info(
        "Claude usage for %s: cache_create=%s cache_read=%s input_units=%s output_units=%s total_input_units=%s",
        purpose,
        usage_metrics["cache_creation_input_tokens"],
        usage_metrics["cache_read_input_tokens"],
        usage_metrics["input_tokens"],
        usage_metrics["output_tokens"],
        total_input_tokens,
    )
    logger.debug(
        "Claude prompt caching for %s: %s",
        purpose,
        "hit"
        if cache_hit
        else "miss"
        if cache_miss
        else "warming_or_no_read_yet",
    )


def _call_openrouter(messages: list[dict[str, Any]]) -> dict[str, Any]:
    if not config.OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not configured.")

    payload = {
        "model": config.LLM_MODEL,
        "messages": messages,
        "temperature": config.LLM_TEMPERATURE,
        "max_tokens": config.LLM_MAX_TOKENS,
    }

    try:
        response = requests.post(
            config.OPENROUTER_BASE_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=60,
        )
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        body = exc.response.text if exc.response is not None else ""
        raise RuntimeError(f"OpenRouter HTTP {status_code}: {body}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"OpenRouter network error: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("OpenRouter returned invalid JSON") from exc


def _anthropic_payload_from_messages(
    messages: list[dict[str, Any]],
    *,
    request_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    system_parts: list[str] = []
    anthropic_messages: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role") or "").strip().lower()
        content = str(message.get("content") or "")
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
            continue
        anthropic_messages.append(
            {
                "role": "assistant" if role == "assistant" else "user",
                "content": content,
            }
        )

    payload: dict[str, Any] = {
        "model": config.LLM_MODEL,
        "max_tokens": config.LLM_MAX_TOKENS,
        "messages": anthropic_messages or [{"role": "user", "content": "Hello"}],
    }
    payload["temperature"] = config.LLM_TEMPERATURE
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)
    request_options = request_options or {}
    stable_prefix_text = str(request_options.get("stable_prefix_text") or "")
    cache_requested = bool(request_options.get("enable_prompt_caching"))
    cache_enabled = cache_requested and _should_enable_claude_prompt_cache(stable_prefix_text)
    if cache_enabled:
        payload["cache_control"] = _claude_cache_control_payload()
    elif cache_requested:
        logger.debug(
            "Claude prompt caching skipped for %s: enabled=%s provider=%s stable_prefix_chars=%s threshold=%s",
            str(request_options.get("purpose") or "anthropic_request"),
            config.CLAUDE_PROMPT_CACHING_ENABLED,
            config.LLM_PROVIDER,
            len(stable_prefix_text),
            _CLAUDE_PROMPT_CACHE_MIN_CHARS,
        )
    return payload


def _call_anthropic(
    messages: list[dict[str, Any]],
    *,
    request_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not config.ANTHROPIC_API_KEY:
        raise RuntimeError("Anthropic API key is not configured.")
    request_options = request_options or {}
    payload = _anthropic_payload_from_messages(messages, request_options=request_options)

    try:
        response = requests.post(
            config.ANTHROPIC_BASE_URL,
            json=payload,
            headers={
                "x-api-key": config.ANTHROPIC_API_KEY,
                "anthropic-version": config.ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            timeout=60,
        )
        response.raise_for_status()
        response_json = response.json()
        _log_claude_usage_metrics(
            response_json,
            purpose=str(request_options.get("purpose") or "anthropic_request"),
        )
        return response_json
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        body = exc.response.text if exc.response is not None else ""
        raise RuntimeError(f"Anthropic HTTP {status_code}: {body}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Anthropic network error: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("Anthropic returned invalid JSON") from exc


def _call_llm(
    messages: list[dict[str, Any]],
    *,
    anthropic_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider = config.LLM_PROVIDER
    if provider == "anthropic":
        return _call_anthropic(messages, request_options=anthropic_options)
    if provider == "openrouter":
        return _call_openrouter(messages)
    if config.ANTHROPIC_API_KEY:
        return _call_anthropic(messages, request_options=anthropic_options)
    return _call_openrouter(messages)


def _extract_text(response_json: dict[str, Any]) -> str:
    if isinstance(response_json.get("content"), list):
        text_parts: list[str] = []
        for item in response_json.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text") or ""))
        return "".join(text_parts).strip()

    choices = response_json.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return message.get("content") or ""


def _strip_leak_lines(text: str) -> str:
    cleaned: list[str] = []
    for line in text.splitlines():
        if any(re.match(pattern, line, flags=re.IGNORECASE) for pattern in _LEAK_PATTERNS):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def _trim_to_expected_start(text: str, scenario_name: str) -> str:
    markers = _EXPECTED_SECTION_MARKERS.get(scenario_name, [])
    best_idx: int | None = None
    for marker in markers:
        idx = text.find(marker)
        if idx != -1 and (best_idx is None or idx < best_idx):
            best_idx = idx
    if best_idx is not None:
        return text[best_idx:].strip()
    return text.strip()


def _extract_multi_audience_sections(text: str) -> str:
    pattern = re.compile(
        r"(?ims)"
        r"^\s*(?:#+\s*)?(?:\*\*)?For the Executive(?:\*\*)?(?:\s*\([^)]*\))?\s*:?\s*$"
        r"(.*?)"
        r"^\s*(?:#+\s*)?(?:\*\*)?For the Security Engineer(?:\*\*)?(?:\s*\([^)]*\))?\s*:?\s*$"
        r"(.*?)"
        r"^\s*(?:#+\s*)?(?:\*\*)?For the Developer(?:\*\*)?(?:\s*\([^)]*\))?\s*:?\s*$"
        r"(.*)$"
    )
    match = pattern.search(text)
    if not match:
        return text.strip()

    executive, security, developer = (part.strip() for part in match.groups())
    sections = [
        "### For the Executive",
        executive,
        "",
        "### For the Security Engineer",
        security,
        "",
        "### For the Developer",
        developer,
    ]
    return "\n".join(sections).strip()


def _clean_multi_audience_body(text: str) -> str:
    cleaned: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped:
            cleaned.append(line)
            continue
        rewritten = line
        for marker in _MULTI_AUDIENCE_META_CLAUSE_MARKERS:
            idx = rewritten.find(marker)
            if idx != -1:
                rewritten = rewritten[:idx].rstrip()
        stripped = rewritten.strip()
        lowered = stripped.lower()
        if not stripped:
            continue
        if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in _MULTI_AUDIENCE_META_PATTERNS):
            continue
        if re.match(r"^\s*total vulnerability records\s*:", stripped, flags=re.IGNORECASE):
            continue
        if re.match(r"^\s*the vulnerabilities are all in\b", stripped, flags=re.IGNORECASE):
            continue
        if re.match(r"^\s*\d+(?:-\d+)?\s*:\s*", stripped):
            continue
        cleaned.append(rewritten)
    text = "\n".join(cleaned)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_first_markdown_table(text: str) -> str:
    lines = text.splitlines()
    for idx in range(len(lines) - 1):
        if "|" not in lines[idx] or "|" not in lines[idx + 1]:
            continue
        if not re.match(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$", lines[idx + 1]):
            continue
        table_lines = [lines[idx].rstrip(), lines[idx + 1].rstrip()]
        for follow in lines[idx + 2:]:
            if "|" not in follow.strip():
                break
            table_lines.append(follow.rstrip())
        return "\n".join(line for line in table_lines if line.strip()).strip()
    return ""


def _extract_code_blocks(text: str) -> list[str]:
    return [match.group(0).strip() for match in re.finditer(r"```[\s\S]*?```", text)]


def _clean_executive_section(text: str) -> str:
    cleaned = _clean_multi_audience_body(text)
    if not cleaned:
        return ""
    kept: list[str] = []
    for line in cleaned.splitlines():
        stripped = line.strip()
        if not stripped:
            if kept and kept[-1] != "":
                kept.append("")
            continue
        if re.match(
            r"^\s*(?:#+\s*)?(?:\*\*)?For the Executive(?:\*\*)?(?:\s*\([^)]*\))?\s*:?\s*$",
            stripped,
            flags=re.IGNORECASE,
        ):
            continue
        if re.fullmatch(r"\(\s*2-3 sentences:.*\)", stripped, flags=re.IGNORECASE):
            continue
        if stripped.startswith("|") or stripped.startswith("```"):
            continue
        if re.match(r"^\s*\d+\.", stripped):
            continue
        kept.append(stripped)
    result = "\n".join(kept).strip()
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result


def _clean_table_section(text: str) -> str:
    cleaned = _clean_multi_audience_body(text)
    if not cleaned:
        return ""
    table = _extract_first_markdown_table(cleaned)
    return table.strip()


def _clean_developer_section(text: str) -> str:
    cleaned = _clean_multi_audience_body(text)
    if not cleaned:
        return ""
    table = _extract_first_markdown_table(cleaned)
    code_blocks = _extract_code_blocks(cleaned)
    parts: list[str] = []
    if table:
        parts.append(table)
    if code_blocks:
        parts.append("\n\n".join(code_blocks))
    return "\n\n".join(parts).strip()


def _extract_named_audience_body(text: str, audience: str) -> str:
    audience_patterns = {
        "executive": "For the Executive",
        "security": "For the Security Engineer",
        "developer": "For the Developer",
    }
    current = audience_patterns[audience]
    other_headers = [label for key, label in audience_patterns.items() if key != audience]
    header_pattern = re.compile(
        rf"(?ims)^\s*(?:#+\s*)?(?:\*\*)?{re.escape(current)}(?:\*\*)?(?:\s*\([^)]*\))?\s*:?\s*$"
    )
    header_match = header_pattern.search(text)
    if not header_match:
        return ""
    start = header_match.end()
    remaining = text[start:]
    next_header_pattern = re.compile(
        rf"(?ims)^\s*(?:#+\s*)?(?:\*\*)?(?:{'|'.join(re.escape(label) for label in other_headers)})(?:\*\*)?(?:\s*\([^)]*\))?\s*:?\s*$"
    )
    next_match = next_header_pattern.search(remaining)
    if next_match:
        return remaining[:next_match.start()].strip()
    return remaining.strip()


def _repair_multi_audience_output(text: str) -> str:
    text = _clean_multi_audience_body(text)
    if not text:
        return text

    executive_raw = _extract_named_audience_body(text, "executive")
    security_raw = _extract_named_audience_body(text, "security")
    developer_raw = _extract_named_audience_body(text, "developer")

    has_any_named_section = any([executive_raw, security_raw, developer_raw])
    if not has_any_named_section:
        executive_raw = text.strip()

    executive = _clean_executive_section(executive_raw)
    security = _clean_table_section(security_raw)
    developer = _clean_developer_section(developer_raw)

    repaired = [
        "### For the Executive",
        executive or "No evidence provided.",
        "",
        "### For the Security Engineer",
        security or "No evidence provided.",
        "",
        "### For the Developer",
        developer or "No evidence provided.",
    ]
    return "\n".join(repaired).strip()


def _normalize_headings(text: str, scenario_name: str) -> str:
    if scenario_name == "multi_audience":
        text = _extract_multi_audience_sections(text)
        text = _repair_multi_audience_output(text)
        lines = text.splitlines()
        normalized: list[str] = []
        heading_map = {
            "for the executive": "### For the Executive",
            "for the security engineer": "### For the Security Engineer",
            "for the developer": "### For the Developer",
        }
        for line in lines:
            stripped = line.strip()
            plain = re.sub(r"^[#\s*]+|[*\s]+$", "", stripped).strip().lower()
            plain = re.sub(r"\s*\([^)]*\)\s*$", "", plain).strip()
            plain = plain.rstrip(":").strip()
            if plain in heading_map:
                normalized.append(heading_map[plain])
                continue
            if re.fullmatch(r"\(\s*2-3 sentences:.*\)", stripped, flags=re.IGNORECASE):
                continue
            if stripped.lower().startswith("(use a markdown table with these columns exactly:"):
                continue
            if stripped.lower() == "after the table, provide one fenced bash block if ecosystem is obvious)":
                continue
            if stripped.startswith("`Vulnerability | Severity | Reachability | Dependency Relation | Strongest Evidence`"):
                continue
            if stripped.startswith("`Package | Current State | Required Change | Evidence`"):
                continue
            normalized.append(line)
        return "\n".join(normalized).strip()

    if scenario_name == "explainability_mode":
        replacements = {
            "Path Claim": "**Path Claim**",
            "Evidence Correlation": "**Evidence Correlation**",
            "Conflict Check": "**Conflict Check**",
            "Confidence": "**Confidence**",
        }
        lines = text.splitlines()
        normalized: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped in replacements:
                normalized.append(replacements[stripped])
            else:
                normalized.append(line)
        return "\n".join(normalized).strip()
    return text.strip()


def _strip_case_prefixes(text: str) -> str:
    return re.sub(r"^\s*Case\s+[ADE]\s*[:\-]?\s*", "", text, flags=re.IGNORECASE).strip()


def _sanitize_llm_output(scenario_name: str, text: str) -> str:
    text = (text or "").strip()
    if not text:
        return text
    text = _strip_case_prefixes(text)
    text = _trim_to_expected_start(text, scenario_name)
    text = _strip_leak_lines(text)
    text = _normalize_headings(text, scenario_name)
    return text.strip()


def _extract_report_sections(text: str, headers: list[str]) -> dict[str, str]:
    if not text.strip():
        return {}
    header_alt = "|".join(re.escape(item) for item in headers)
    pattern = re.compile(
        rf"(?im)^\s*(?:#+\s*)?(?:\*\*)?({header_alt})(?:\*\*)?\s*:?\s*$"
    )
    matches = list(pattern.finditer(text))
    if not matches:
        return {}
    sections: dict[str, str] = {}
    for idx, match in enumerate(matches):
        raw_header = match.group(1).strip()
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        sections[raw_header.lower()] = body
    return sections


def _clean_report_section_body(text: str) -> str:
    if not text:
        return ""
    lowered = text.lower()
    cutoff_positions = [
        lowered.find(marker) for marker in _REPORT_LEAK_CUTOFF_MARKERS if marker in lowered
    ]
    if cutoff_positions:
        text = text[: min(cutoff_positions)].strip()

    cleaned_lines: list[str] = []
    for line in text.splitlines():
        if any(re.match(pattern, line, flags=re.IGNORECASE) for pattern in _REPORT_PROMPT_ECHO_LINE_PATTERNS):
            continue
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _sanitize_structured_report_narrative(text: str, headers: list[str]) -> str:
    sections = _extract_report_sections(text, headers)
    if not sections:
        return ""
    parts: list[str] = []
    for header in headers:
        key = header.lower()
        body = _clean_report_section_body(sections.get(key, ""))
        parts.append(f"## {header}")
        parts.append(body or "No evidence provided.")
        parts.append("")
    return "\n".join(parts).strip()


def _sanitize_structured_report_sections(text: str, headers: list[str]) -> dict[str, str]:
    sections = _extract_report_sections(text, headers)
    if not sections:
        return {}
    return {
        header.lower(): (_clean_report_section_body(sections.get(header.lower(), "")) or "No evidence provided.")
        for header in headers
    }


def sanitize_stakeholder_report_narrative(text: str) -> str:
    return _sanitize_structured_report_narrative(text, _STAKEHOLDER_REPORT_HEADERS)


def sanitize_developer_report_narrative(text: str) -> str:
    return _sanitize_structured_report_narrative(text, _DEVELOPER_REPORT_HEADERS)


def _section_map_to_report_keys(sections: dict[str, str], mapping: dict[str, str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for report_key, heading in mapping.items():
        body = sections.get(heading.lower(), "")
        if body:
            output[report_key] = body
    return output


def _format_rule_block(title: str, items: list[str]) -> str:
    body = "\n".join(f"- {item}" for item in items)
    return f"{title}:\n{body}"


def _build_report_prompt_components(
    *,
    role_instruction: str,
    section_headers: list[str],
    writing_style: list[str],
    allowed_evidence: list[str],
    forbidden_behavior: list[str],
    output_schema: dict[str, str],
    final_instruction: str,
) -> tuple[str, str, str]:
    audience_system_prompt = textwrap.dedent(role_instruction).strip()
    section_lines = "\n".join(f"## {header}" for header in section_headers)
    schema_lines = "\n".join(f"- {header}: {instruction}" for header, instruction in output_schema.items())
    stable_prefix_prompt = "\n\n".join(
        [
            "Return Markdown with exactly these sections:",
            section_lines,
            _format_rule_block("Writing style", writing_style),
            _format_rule_block("Allowed evidence", allowed_evidence),
            _format_rule_block("Forbidden behavior", forbidden_behavior),
            f"Output schema:\n{schema_lines}",
        ]
    ).strip()
    return audience_system_prompt, stable_prefix_prompt, textwrap.dedent(final_instruction).strip()


def _compact_stakeholder_prompt_payload(report_obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "project": report_obj.get("project"),
        "scan_id": report_obj.get("scan_id"),
        "generated_at": report_obj.get("generated_at"),
        "posture_summary": report_obj.get("posture_summary") or {},
        "affected_areas": (report_obj.get("affected_areas") or [])[:5],
        "top_priority_actions": [
            {
                "component": item.get("component"),
                "current_version": item.get("current_version"),
                "target_version": item.get("target_version"),
                "affected_area": item.get("affected_area"),
                "related_case_count": item.get("related_case_count"),
                "related_cves": item.get("related_cves"),
                "severity": item.get("severity"),
                "decision_tier_raw": item.get("decision_tier"),
                "decision_tier_label": present_decision_tier(item.get("decision_tier"), "stakeholder"),
                "reachability_raw": item.get("reachability_verdict"),
                "reachability_label": present_reachability(item.get("reachability_verdict"), "stakeholder"),
                "why_now": item.get("why_now"),
                "impact_basis": item.get("impact_basis"),
                "required_management_action": item.get("required_management_action"),
            }
            for item in (report_obj.get("top_priority_actions") or [])[:5]
        ],
        "impact_summary": report_obj.get("impact_summary") or {},
        "current_action_snapshot": report_obj.get("current_action_snapshot") or {},
        "recommended_management_actions": (report_obj.get("recommended_management_actions") or [])[:4],
        "next_verification_checkpoint": report_obj.get("next_verification_checkpoint") or {},
    }


def _compact_developer_prompt_payload(report_obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "project": report_obj.get("project"),
        "scan_id": report_obj.get("scan_id"),
        "generated_at": report_obj.get("generated_at"),
        "triage_summary": report_obj.get("triage_summary") or {},
        "immediate_fix_clusters": [
            {
                "package": item.get("package"),
                "current_version": item.get("current_version"),
                "target_version": item.get("target_version"),
                "related_case_count": item.get("related_case_count"),
                "related_cves": item.get("related_cves"),
                "reachability_raw": item.get("strongest_reachability"),
                "reachability_label": present_reachability(item.get("strongest_reachability"), "developer"),
                "why_fix_now": item.get("why_fix_now"),
                "next_action": item.get("next_action"),
                "call_evidence": [
                    {
                        "vuln_id": evidence.get("vuln_id"),
                        "reachability_raw": evidence.get("reachability_verdict"),
                        "reachability_label": present_reachability(evidence.get("reachability_verdict"), "developer"),
                        "scope_label": present_evidence_scope(evidence.get("evidence_scope"), "developer"),
                        "call_locations": evidence.get("call_locations"),
                    }
                    for evidence in (item.get("call_evidence") or [])[:4]
                ],
                "verification_target": item.get("verification_target"),
            }
            for item in (report_obj.get("immediate_fix_clusters") or [])[:5]
        ],
        "planned_upgrade_backlog": {
            **(report_obj.get("planned_upgrade_backlog") or {}),
            "backlog_clusters": [
                {
                    "package": item.get("package"),
                    "current_version": item.get("current_version"),
                    "target_version": item.get("target_version"),
                    "related_case_count": item.get("related_case_count"),
                    "decision_tier_raw": item.get("decision_tier"),
                    "decision_tier_label": present_decision_tier(item.get("decision_tier"), "developer"),
                    "reachability_raw": item.get("reachability_verdict"),
                    "reachability_label": present_reachability(item.get("reachability_verdict"), "developer"),
                    "reason_not_fix_now": item.get("reason_not_fix_now"),
                    "recommended_next_window_action": item.get("recommended_next_window_action"),
                }
                for item in ((report_obj.get("planned_upgrade_backlog") or {}).get("backlog_clusters") or [])[:6]
            ],
        },
        "verification_checklist": (report_obj.get("verification_checklist") or [])[:5],
        "verification_delta": report_obj.get("verification_delta") or {},
        "detailed_technical_findings": [
            {
                "vuln_id": item.get("vuln_id"),
                "component": item.get("component"),
                "current_version": item.get("current_version"),
                "severity": item.get("severity"),
                "decision_tier_raw": item.get("decision_tier"),
                "decision_tier_label": present_decision_tier(item.get("decision_tier"), "developer"),
                "reachability_raw": item.get("reachability_verdict"),
                "reachability_label": present_reachability(item.get("reachability_verdict"), "developer"),
                "fix_versions": item.get("fix_versions"),
                "impact_summary": item.get("impact_summary"),
            }
            for item in (report_obj.get("detailed_technical_findings") or [])[:8]
        ],
    }


def _build_cached_report_messages(
    *,
    audience_system_prompt: str,
    stable_prefix_prompt: str,
    dynamic_payload: str,
    final_generation_instruction: str,
) -> tuple[list[dict[str, Any]], str]:
    """
    Keep the reusable prefix before the report JSON so Anthropic can reuse cached prompt
    tokens across many report generations. The report JSON stays later because it changes
    per project and scan, so caching that part would have little reuse value.
    """
    messages = [
        {"role": "system", "content": audience_system_prompt},
        {"role": "user", "content": stable_prefix_prompt},
        {"role": "user", "content": dynamic_payload},
        {"role": "user", "content": final_generation_instruction},
    ]
    stable_prefix_text = "\n\n".join([audience_system_prompt, stable_prefix_prompt])
    return messages, stable_prefix_text


def explain(scenario_name: str, evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    if not evidence:
        return "No evidence was returned from the graph for this query. The system cannot provide an explanation."

    try:
        user_prompt = build_prompt(scenario_name, evidence, summary)
    except ValueError:
        return f"Warning: No prompt template defined for scenario '{scenario_name}'."
    response_json = _call_llm(
        [
            {"role": "system", "content": _SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_prompt},
        ]
    )
    return _sanitize_llm_output(scenario_name, _extract_text(response_json))


def generate_stakeholder_report_narrative_sections(report_obj: dict[str, Any]) -> dict[str, str]:
    """
    LLM augmentation layer for stakeholder report prose.
    """
    payload = json.dumps(_compact_stakeholder_prompt_payload(report_obj), ensure_ascii=False, indent=2)
    audience_system_prompt, stable_prefix_prompt, final_generation_instruction = _build_report_prompt_components(
        role_instruction="""\
        Role: security posture summarizer for engineering managers, product stakeholders, and release decision-makers.

        The report JSON is already the source of truth. Your job is to transform deterministic findings into readable,
        business-facing security language without changing the underlying facts.
        """,
        section_headers=_STAKEHOLDER_REPORT_HEADERS,
        writing_style=[
            "Use plain business-readable English and keep the tone calm, credible, and concise.",
            "Connect security exposure to release, coordination, ownership, or timing decisions when the evidence supports that connection.",
            "Prefer natural prose with short paragraphs over repetitive sentence templates.",
            "Translate internal labels into human language before you mention any raw label.",
        ],
        allowed_evidence=[
            "Use only facts present in the report JSON, including counts, areas, tiers, versions, and verification notes.",
            "State uncertainty honestly when evidence is incomplete or mapping is partial.",
            "You may describe direct versus likely evidence, but do not upgrade likely evidence into confirmed evidence.",
        ],
        forbidden_behavior=[
            "Do not invent package names, versions, counts, file paths, commands, fix versions, or risk scores.",
            "Do not use internal machine labels like confirmed_reachable, likely_reachable, no_sink_data, or fix_now as the main audience-facing wording.",
            "Do not repeat the same fact in every section and do not mention prompt mechanics or report JSON mechanics.",
        ],
        output_schema={
            "What Needs Attention Now": "Explain the highest-priority exposure in practical terms and identify the most important current-release items.",
            "Why It Matters Now": "Explain business or release impact, including why timing matters now rather than later.",
            "What Action Or Approval Is Needed Next": "State what decision, approval, or coordination step should happen next.",
            "What Remains Under Observation": "Explain what is still uncertain, what can wait, and why incomplete evidence is not the same as safety.",
        },
        final_instruction="""\
        Generate the stakeholder narrative now.
        Keep the report grounded in the supplied JSON, concise but not robotic, and limited to the required sections.
        """,
    )
    dynamic_payload = f"REPORT JSON:\n{payload}"
    messages, stable_prefix_text = _build_cached_report_messages(
        audience_system_prompt=audience_system_prompt,
        stable_prefix_prompt=stable_prefix_prompt,
        dynamic_payload=dynamic_payload,
        final_generation_instruction=final_generation_instruction,
    )
    response_json = _call_llm(
        [{"role": "system", "content": _SYSTEM_INSTRUCTION}, *messages],
        anthropic_options={
            "enable_prompt_caching": True,
            "stable_prefix_text": "\n\n".join([_SYSTEM_INSTRUCTION, stable_prefix_text]),
            "purpose": "stakeholder_report_narrative",
        },
    )
    raw = _extract_text(response_json).strip()
    sanitized = _sanitize_structured_report_sections(raw, _STAKEHOLDER_REPORT_HEADERS)
    return _section_map_to_report_keys(
        sanitized,
        {
            "what_needs_attention_now": "What Needs Attention Now",
            "why_it_matters_now": "Why It Matters Now",
            "decision_needed_next": "What Action Or Approval Is Needed Next",
            "what_remains_uncertain": "What Remains Under Observation",
        },
    )


def generate_developer_report_narrative_sections(report_obj: dict[str, Any]) -> dict[str, str]:
    """
    LLM augmentation layer for developer remediation report prose.
    """
    payload = json.dumps(_compact_developer_prompt_payload(report_obj), ensure_ascii=False, indent=2)
    audience_system_prompt, stable_prefix_prompt, final_generation_instruction = _build_report_prompt_components(
        role_instruction="""\
        Role: remediation-oriented application security engineer supporting backend, platform, and AppSec teams.

        The report JSON is already the source of truth. Your job is to turn that evidence into a practical remediation note
        that helps engineers decide what to fix next and how to verify the result.
        """,
        section_headers=_DEVELOPER_REPORT_HEADERS,
        writing_style=[
            "Be technical, direct, and evidence-first without sounding like a log file.",
            "Use short paragraphs or compact bullets inside sections when it improves readability.",
            "Separate direct call evidence from weaker import or usage evidence.",
            "Translate raw labels into developer-facing language first; raw labels may appear only where they add diagnostic value.",
        ],
        allowed_evidence=[
            "Use only facts in the report JSON, including package names, versions, queue counts, fix versions, verification targets, and evidence scope.",
            "Call out production-path versus test-only evidence when the JSON supports that distinction.",
            "Explain why a case is not in the immediate queue when the JSON points to weaker evidence or missing sink data.",
        ],
        forbidden_behavior=[
            "Do not invent commands, file paths, package names, fix versions, or reachability evidence.",
            "Do not describe likely evidence as confirmed evidence.",
            "Do not treat no sink data as proof of safety, and do not repeat the same queue statistics in every section.",
        ],
        output_schema={
            "Queue Overview": "Summarize the shape of the remediation queue and the strongest evidence distribution.",
            "Strongest Evidence": "Explain where the best evidence currently sits and why it is urgent.",
            "Immediate Next Steps": "Describe the most direct remediation path for the leading queue item or cluster.",
            "Verification Guidance": "Explain what to rerun or recheck after patching and what success should look like.",
            "What Is Still Uncertain Or Deferred": "Explain which items stay deferred or under observation and why incomplete evidence still matters.",
        },
        final_instruction="""\
        Generate the developer remediation narrative now.
        Keep it grounded in the supplied JSON, practically useful for remediation work, and limited to the required sections.
        """,
    )
    dynamic_payload = f"REPORT JSON:\n{payload}"
    messages, stable_prefix_text = _build_cached_report_messages(
        audience_system_prompt=audience_system_prompt,
        stable_prefix_prompt=stable_prefix_prompt,
        dynamic_payload=dynamic_payload,
        final_generation_instruction=final_generation_instruction,
    )
    response_json = _call_llm(
        [{"role": "system", "content": _SYSTEM_INSTRUCTION}, *messages],
        anthropic_options={
            "enable_prompt_caching": True,
            "stable_prefix_text": "\n\n".join([_SYSTEM_INSTRUCTION, stable_prefix_text]),
            "purpose": "developer_report_narrative",
        },
    )
    raw = _extract_text(response_json).strip()
    sanitized = _sanitize_structured_report_sections(raw, _DEVELOPER_REPORT_HEADERS)
    return _section_map_to_report_keys(
        sanitized,
        {
            "queue_overview": "Queue Overview",
            "strongest_evidence": "Strongest Evidence",
            "immediate_next_steps": "Immediate Next Steps",
            "verification_guidance": "Verification Guidance",
            "remaining_uncertainty": "What Is Still Uncertain Or Deferred",
        },
    )


def generate_stakeholder_report_narrative(report_obj: dict[str, Any]) -> str:
    sections = generate_stakeholder_report_narrative_sections(report_obj)
    return "\n\n".join(
        [
            "## What Needs Attention Now",
            sections.get("what_needs_attention_now", "No evidence provided."),
            "",
            "## Why It Matters Now",
            sections.get("why_it_matters_now", "No evidence provided."),
            "",
            "## What Action Or Approval Is Needed Next",
            sections.get("decision_needed_next", "No evidence provided."),
            "",
            "## What Remains Under Observation",
            sections.get("what_remains_uncertain", "No evidence provided."),
        ]
    ).strip()


def generate_developer_report_narrative(report_obj: dict[str, Any]) -> str:
    sections = generate_developer_report_narrative_sections(report_obj)
    return "\n\n".join(
        [
            "## Queue Overview",
            sections.get("queue_overview", "No evidence provided."),
            "",
            "## Strongest Evidence",
            sections.get("strongest_evidence", "No evidence provided."),
            "",
            "## Immediate Next Steps",
            sections.get("immediate_next_steps", "No evidence provided."),
            "",
            "## Verification Guidance",
            sections.get("verification_guidance", "No evidence provided."),
            "",
            "## What Is Still Uncertain Or Deferred",
            sections.get("remaining_uncertainty", "No evidence provided."),
        ]
    ).strip()


def get_scenarios() -> dict[str, str]:
    return {
        "project_overview": "Project Posture Overview",
        "dev_explain": config.SCENARIOS["dev_explain"],
    }


def run_pipeline(scenario_name: str, overrides: dict[str, Any]) -> dict[str, Any]:
    import time
    from backend.retrieval_scenarios import get_scenario
    from backend.services.evidence_service import KnowledgeRetriever

    try:
        scen_def = get_scenario(scenario_name)
    except Exception as e:
        return {"error": f"Unknown scenario or error parsing: {scenario_name} - {e}"}

    params: dict[str, Any] = {}
    for q in scen_def.queries:
        params.update(q.params)
    params.update(overrides)

    t0 = time.time()
    retriever = KnowledgeRetriever()
    evidence_records, summary, meta = retriever.build_evidence(scenario_name, params)
    evidence_records = enrich_evidence_with_semgrep(evidence_records)
    t1 = time.time()
    meta["db_time_ms"] = round((t1 - t0) * 1000, 2)

    tllm_0 = time.time()
    explanation = explain(scenario_name, evidence_records, summary)
    tllm_1 = time.time()
    meta["llm_time_ms"] = round((tllm_1 - tllm_0) * 1000, 2)

    return {"explanation": explanation, "evidence": evidence_records, "query_meta": meta}
