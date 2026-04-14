"""
backend/services/llm_service.py - LLM Explanation Engine.

Uses OpenRouter chat completions.
"""

from __future__ import annotations

from typing import Any
import json
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
7. If Semgrep reachability evidence is present, prioritize it when deciding exploitability."""


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

        OUTPUT FORMAT (exactly these sections):
        ### Exploitability Verdict
        - One sentence verdict: Reachable / Not confirmed reachable / Unknown.

        ### Evidence Trace
        - Bullet points with concrete evidence values from the context:
          file:line, dependency depth, semgrep verdict, sink functions, call locations.

        ### Technical Reasoning
        - Explain how the verdict follows from the evidence.
        - Mention any missing or weak evidence explicitly.

        ### Remediation Plan
        - Recommended fixed version (if available) and exact upgrade action.
        - If no fix is available, provide temporary mitigation actions.

        ### Confidence
        - High: direct Semgrep call locations exist.
        - Medium: Semgrep verdict exists but no call locations.
        - Low: Semgrep data missing or contradictory.
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
        - Use this reasoning order:
          Semgrep reachability facts > dependency path facts > risk metrics.
        - Trace the shortest path and explicitly state the depth (hops).
        - If Semgrep and graph-path evidence disagree, report the conflict and explain which evidence is stronger.
        - Do not conclude "reachable" unless Semgrep facts support it.
        - Output exactly these sections:
          1) `Path Claim`
          2) `Evidence Correlation`
          3) `Conflict Check`
          4) `Confidence (High/Medium/Low)`
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
        - Every section must reference Semgrep verdict when available.
        - If Semgrep is missing, say "No Semgrep evidence provided."
        - Keep claims scoped to evidence only.
        - Generate exactly three sections separated by headers:
        ### For the Executive
        (1-2 sentences: business risk + whether exploitability is confirmed)

        ### For the Security Engineer
        (List CVE, KEV, CVSS/EPSS, Semgrep verdict, and main technical evidence)

        ### For the Developer
        (Provide dependency, file/call location if known, and exact fix action)
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
        - Describe the total counts of Critical / High / Medium / Low alerts.
        - Highlight if there are any KEV alerts.
        - If the project has heavy critical exposure, emphasize the need for an audit.
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
        - Identify core vulnerable component and direct/transitive paths.
        - Infer blast radius from BOTH:
          1) graph spread (depth, number of affected paths)
          2) Semgrep exploitability evidence (verdict + call locations).
        - If Semgrep is likely_unreachable with no call locations, treat impact as conditional, not confirmed.
        - Output exactly these sections:
          1) `Blast Radius Verdict`
          2) `Supporting Evidence`
          3) `Operational Impact`
          4) `Mitigation Priority`
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
        "reasoning": {"enabled": True},
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


def explain(scenario_name: str, evidence: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    if not evidence:
        return "No evidence was returned from the graph for this query. The system cannot provide an explanation."

    builder_fn = _PROMPT_BUILDERS.get(scenario_name)
    if not builder_fn:
        return f"Warning: No prompt template defined for scenario '{scenario_name}'."

    user_prompt = builder_fn(evidence, summary)
    response_json = _call_openrouter(
        [
            {"role": "system", "content": _SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_prompt},
        ]
    )
    return _extract_text(response_json)


def get_scenarios() -> dict[str, str]:
    res = dict(config.SCENARIOS)
    res["project_overview"] = "Project Posture Overview"
    res["arch_impact"] = "Blast Radius Analysis"
    res["custom"] = "Custom Question Q&A"
    return res


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