"""
Export LLM analysis prompts and answers to a Markdown file for one project.

Runs the same evidence retrieval + prompt building + OpenRouter flow used by the
dashboard, but writes each scenario's prompt and answer to a reviewable .md file.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from backend.services.evidence_service import KnowledgeRetriever
from backend.services.llm_service import (
    build_prompt,
    explain,
    get_system_instruction,
)
from backend.services.semgrep_context_service import enrich_evidence_with_semgrep


SCENARIOS: list[tuple[str, str]] = [
    ("project_overview", "Overview"),
    ("dev_explain", "Case A - Developer-focused vulnerability explanation"),
    ("explainability_mode", "Case B - Explainability with confidence score"),
    ("multi_audience", "Case C - Multi-audience output"),
    ("arch_impact", "Case D - Blast Radius analysis"),
]


def _slug(text: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in text).strip("_")


def _build_overrides(project_name: str, vuln_id: str, component_id: str) -> dict[str, dict[str, str]]:
    project_only = {"project_name": project_name}
    project_drilldown = {
        "project_name": project_name,
        "vuln_id": vuln_id,
        "component_id": component_id,
    }
    return {
        "project_overview": dict(project_only),
        "dev_explain": dict(project_drilldown),
        "explainability_mode": dict(project_drilldown),
        "multi_audience": dict(project_drilldown),
        "arch_impact": dict(project_drilldown),
    }


def _render_section(
    scenario_name: str,
    title: str,
    overrides: dict[str, str],
    retriever: KnowledgeRetriever,
) -> tuple[str, dict[str, object]]:
    started = time.time()
    evidence_records, summary, meta = retriever.build_evidence(scenario_name, overrides)
    evidence_records = enrich_evidence_with_semgrep(evidence_records)
    db_time_ms = round((time.time() - started) * 1000, 2)

    prompt = build_prompt(scenario_name, evidence_records, summary)

    llm_started = time.time()
    answer = explain(scenario_name, evidence_records, summary)
    llm_time_ms = round((time.time() - llm_started) * 1000, 2)

    body = [
        f"## {title}",
        "",
        f"- `scenario`: `{scenario_name}`",
        f"- `evidence_count`: `{len(evidence_records)}`",
        f"- `db_time_ms`: `{db_time_ms}`",
        f"- `llm_time_ms`: `{llm_time_ms}`",
        "",
        "### Prompt",
        "",
        "```text",
        get_system_instruction().strip(),
        "```",
        "",
        "```text",
        prompt.strip(),
        "```",
        "",
        "### Answer",
        "",
        answer.strip() if answer else "_No answer returned._",
        "",
    ]
    meta_out = dict(meta)
    meta_out["db_time_ms"] = db_time_ms
    meta_out["llm_time_ms"] = llm_time_ms
    return "\n".join(body), meta_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Export LLM analysis results to Markdown")
    parser.add_argument("--project", required=True, help="Project full_name")
    parser.add_argument("--vuln-id", required=True, help="Drill-down vulnerability ID")
    parser.add_argument("--component-id", required=True, help="Affected component_id")
    parser.add_argument(
        "--output",
        help="Output markdown path. Defaults to gui_retrieval/reports/<project>_llm_analysis.md",
    )
    args = parser.parse_args()

    output_path = (
        Path(args.output)
        if args.output
        else Path(__file__).resolve().parent / "reports" / f"{_slug(args.project)}_llm_analysis.md"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    retriever = KnowledgeRetriever()
    overrides_by_scenario = _build_overrides(args.project, args.vuln_id, args.component_id)

    lines = [
        f"# LLM Analysis Review - {args.project}",
        "",
        f"- `project`: `{args.project}`",
        f"- `vuln_id`: `{args.vuln_id}`",
        f"- `component_id`: `{args.component_id}`",
        "- `excluded_feature`: `custom question`",
        "",
    ]

    diagnostics: dict[str, dict[str, object]] = {}
    for scenario_name, title in SCENARIOS:
        section, meta = _render_section(
            scenario_name=scenario_name,
            title=title,
            overrides=overrides_by_scenario[scenario_name],
            retriever=retriever,
        )
        lines.append(section)
        diagnostics[scenario_name] = meta

    lines.extend(
        [
            "## Diagnostics",
            "",
            "```text",
            str(diagnostics),
            "```",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(output_path)


if __name__ == "__main__":
    main()
