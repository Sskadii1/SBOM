"""
backend/services/llm_service.py - LLM Explanation Engine.

Uses OpenRouter chat completions.
"""

from __future__ import annotations

from typing import Any
import json
import re
import textwrap
import urllib.error
import urllib.request

import backend.config as config
import backend.services.prompt_service as pf
from backend.services.semgrep_context_service import enrich_evidence_with_semgrep


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


def _call_openrouter(messages: list[dict[str, Any]]) -> dict[str, Any]:
    if not config.OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not configured.")
    if config.LLM_MODEL.startswith("gemini"):
        raise RuntimeError(
            "LLM_MODEL is still set to a Gemini model. "
            "Update .env to an OpenRouter model such as "
            "'nvidia/nemotron-3-super-120b-a12b:free' and restart Streamlit."
        )

    payload = {
        "model": config.LLM_MODEL,
        "messages": messages,
        "temperature": config.LLM_TEMPERATURE,
        "max_tokens": config.LLM_MAX_TOKENS,
    }

    req = urllib.request.Request(
        config.OPENROUTER_BASE_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenRouter network error: {exc}") from exc


def _extract_text(response_json: dict[str, Any]) -> str:
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


def _normalize_headings(text: str, scenario_name: str) -> str:
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


def explain(scenario_name: str, evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    if not evidence:
        return "No evidence was returned from the graph for this query. The system cannot provide an explanation."

    try:
        user_prompt = build_prompt(scenario_name, evidence, summary)
    except ValueError:
        return f"Warning: No prompt template defined for scenario '{scenario_name}'."
    response_json = _call_openrouter(
        [
            {"role": "system", "content": _SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_prompt},
        ]
    )
    return _sanitize_llm_output(scenario_name, _extract_text(response_json))


def get_scenarios() -> dict[str, str]:
    return {
        "project_overview": "Project Posture Overview",
        "dev_explain": config.SCENARIOS["dev_explain"],
        "explainability_mode": config.SCENARIOS["explainability_mode"],
        "multi_audience": config.SCENARIOS["multi_audience"],
        "arch_impact": "Blast Radius Analysis",
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

    if scenario_name == "custom":
        question = overrides.get("question", "Summarize this project.")
        ev_str = json.dumps(evidence_records[:30], indent=2)
        response_json = _call_openrouter(
            [
                {"role": "system", "content": _SYSTEM_INSTRUCTION},
                {"role": "user", "content": f"USER QUESTION: {question}\n\nEVIDENCE:\n{ev_str}"},
            ]
        )
        t2 = time.time()
        meta["llm_time_ms"] = round((t2 - t1) * 1000, 2)
        return {"explanation": _extract_text(response_json), "evidence": evidence_records, "query_meta": meta}

    tllm_0 = time.time()
    explanation = explain(scenario_name, evidence_records, summary)
    tllm_1 = time.time()
    meta["llm_time_ms"] = round((tllm_1 - tllm_0) * 1000, 2)

    return {"explanation": explanation, "evidence": evidence_records, "query_meta": meta}
