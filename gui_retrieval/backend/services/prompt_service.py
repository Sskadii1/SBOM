"""
backend/services/prompt_service.py — Converts evidence records into
human-readable plain-text context blocks for LLM prompts.
"""

from __future__ import annotations
from typing import Any

EvidenceRecord = dict[str, Any]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _na(value: Any, fmt: str = "") -> str:
    if value is None:
        return "N/A"
    if fmt:
        try:
            return format(value, fmt)
        except (TypeError, ValueError):
            pass
    return str(value)


def _yn(value: Any) -> str:
    if value is None:
        return "N/A"
    return "Yes" if value else "No"


def _fix(fix_versions: list) -> str:
    if not fix_versions:
        return "None available"
    shortened = fix_versions[:3]
    suffix = f" (+{len(fix_versions) - 3} more)" if len(fix_versions) > 3 else ""
    return ", ".join(shortened) + suffix


def _dep_chain(rec: EvidenceRecord) -> str:
    chain = rec.get("dependency_chain") or []
    if not chain:
        return ""
    return " → ".join(str(x) for x in chain)


def _location_line(rec: EvidenceRecord) -> str:
    path = rec.get("location_path")
    line = rec.get("location_line")
    if path:
        return f"{path}" + (f" : L{line}" if line else "")
    return ""


def _dependency_descriptor(rec: EvidenceRecord) -> str:
    depth = rec.get("depth")
    is_direct = rec.get("is_direct_dependency")
    if is_direct is True:
        return "Direct dependency"
    if is_direct is False and depth is not None:
        return f"Transitive dependency (depth={depth})"
    if depth is None:
        return ""
    # In this dataset, direct dependencies may appear as depth=1 in
    # component-impact rows and depth=0 in shortest-path rows.
    if depth in (0, 1):
        return f"Direct dependency (depth={depth})"
    return f"Transitive dependency (depth={depth})"


def _vuln_line(rec: EvidenceRecord, idx: int) -> str:
    comp    = _na(rec.get("component"))
    ver     = _na(rec.get("version"))
    vuln    = _na(rec.get("vulnerability"))
    cvss    = _na(rec.get("cvss"), ".1f")
    kev     = _yn(rec.get("kev"))
    epss    = _na(rec.get("epss"), ".4f")
    fix     = _fix(rec.get("fix_versions") or [])
    loc     = _location_line(rec)
    dep_desc = _dependency_descriptor(rec)

    lines = [
        f"  {idx}. {comp} {ver}  →  {vuln}",
        f"     CVSS: {cvss}  |  KEV: {kev}  |  EPSS: {epss}  |  Fix: {fix}",
    ]
    if dep_desc:
        lines.append(f"     Dependency  : {dep_desc}")
    if loc:
        lines.append(f"     Declared at: {loc}")
    chain = _dep_chain(rec)
    if chain:
        lines.append(f"     Dep chain   : {chain}")
    semgrep_verdict = rec.get("reachability_verdict")
    semgrep_sinks = rec.get("semgrep_sink_functions") or []
    semgrep_locs = rec.get("semgrep_call_locations") or []
    if semgrep_verdict:
        lines.append(
            "     Semgrep     : "
            f"verdict={semgrep_verdict}"
            f" | sinks={len(semgrep_sinks)}"
            f" | call_locations={len(semgrep_locs)}"
        )
        if semgrep_sinks:
            lines.append(f"     Sink funcs  : {', '.join(semgrep_sinks[:5])}")
        if semgrep_locs:
            lines.append(f"     Calls       : {', '.join(semgrep_locs[:3])}")
    return "\n".join(lines)


def _summary_block(summary: dict[str, Any]) -> str:
    return (
        f"  Records total      : {summary.get('total_records', 0)}\n"
        f"  KEV hits           : {summary.get('kev_count', 0)}\n"
        f"  Has fix            : {summary.get('has_fix_count', 0)}\n"
        f"  No fix available   : {summary.get('no_fix_count', 0)}\n"
        f"  Max CVSS           : {_na(summary.get('max_cvss'), '.1f')}\n"
        f"  Missing location   : {summary.get('records_missing_location', 0)}"
    )


# ---------------------------------------------------------------------------
# Public formatters — one per scenario
# ---------------------------------------------------------------------------

def format_dev_explain(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    project = _na(evidence[0].get("project") if evidence else None)
    lines: list[str] = [
        f"Project: {project}", "",
        "Overview:", _summary_block(summary), "",
        f"Vulnerable Components ({min(len(evidence), 20)} shown):",
    ]
    seen: set[tuple] = set()
    idx = 1
    for rec in evidence[:20]:
        key = (rec.get("component"), rec.get("vulnerability"))
        if key in seen or rec.get("vulnerability") is None:
            continue
        seen.add(key)
        lines.append(_vuln_line(rec, idx))
        idx += 1
    if not seen:
        lines.append("  (No vulnerability data returned)")
    return "\n".join(lines)


def format_manager_brief(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    lines: list[str] = [
        "Portfolio Security Briefing", "=" * 50, "",
        "Overall Summary:", _summary_block(summary), "",
    ]
    projects: dict[str, dict[str, Any]] = {}
    for rec in evidence:
        proj = rec.get("project") or rec.get("full_name") or "Unknown"
        if proj not in projects:
            projects[proj] = {"risk_score": rec.get("risk_score"), "kev_count": 0,
                              "vuln_count": 0, "vulns": [], "kev_vulns": []}
        entry = projects[proj]
        if rec.get("risk_score") is not None and entry["risk_score"] is None:
            entry["risk_score"] = rec.get("risk_score")
        if rec.get("vulnerability"):
            entry["vuln_count"] += 1
            entry["vulns"].append(rec.get("vulnerability"))
        if rec.get("kev"):
            entry["kev_count"] += 1
            entry["kev_vulns"].append(rec.get("vulnerability"))

    ranked = sorted(projects.items(), key=lambda x: x[1]["risk_score"] or 0, reverse=True)
    lines.append(f"Top Risky Projects ({min(len(ranked), 10)} shown):")
    for i, (proj, data) in enumerate(ranked[:10], 1):
        kev_note = f"  ⚠ KEV: {', '.join(data['kev_vulns'][:3])}" if data["kev_vulns"] else ""
        lines.append(
            f"  {i}. {proj}\n"
            f"     Risk score: {_na(data['risk_score'], '.1f')}  |  "
            f"Vulns: {data['vuln_count']}  |  KEV hits: {data['kev_count']}"
            + (f"\n     {kev_note}" if kev_note else "")
        )

    kev_recs = [r for r in evidence if r.get("kev") and r.get("vulnerability")]
    if kev_recs:
        lines += ["", f"CISA KEV Urgent Items ({len(kev_recs)} total):"]
        for i, rec in enumerate(kev_recs[:15], 1):
            lines.append(
                f"  {i}. [{rec.get('project')}]  {rec.get('component')} {_na(rec.get('version'))}"
                f"  →  {rec.get('vulnerability')}  CVSS: {_na(rec.get('cvss'), '.1f')}"
                f"  Fix: {_fix(rec.get('fix_versions') or [])}"
            )

    recent = [r for r in evidence if r.get("vulnerability")]
    if recent:
        lines += ["", "Recent / Notable Vulnerabilities (sample):"]
        for i, rec in enumerate(recent[:10], 1):
            lines.append(
                f"  {i}. {rec.get('project')}  |  {rec.get('component')} {_na(rec.get('version'))}"
                f"  →  {rec.get('vulnerability')}  KEV: {_yn(rec.get('kev'))}"
            )
    return "\n".join(lines)


def format_triage_queue(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    fix_now: list[EvidenceRecord] = []
    temp_mit: list[EvidenceRecord] = []
    monitor: list[EvidenceRecord] = []

    for rec in evidence:
        if rec.get("vulnerability") is None:
            continue
        cvss = rec.get("cvss") or 0.0
        kev  = rec.get("kev") or False
        has_fix = bool(rec.get("fix_versions"))
        if (cvss >= 7.0 or kev) and has_fix:
            fix_now.append(rec)
        elif cvss >= 7.0 and not has_fix:
            temp_mit.append(rec)
        else:
            monitor.append(rec)

    lines: list[str] = [
        "Vulnerability Triage Queue", "=" * 50, "",
        "Summary:", _summary_block(summary), "",
        f"🔴 FIX NOW  ({len(fix_now)} items — patch available, CVSS ≥ 7.0 or KEV):",
    ]
    if fix_now:
        for i, rec in enumerate(fix_now[:30], 1):
            lines.append(
                f"  {i}. [{rec.get('project')}]  "
                f"{rec.get('component')} {_na(rec.get('version'))}"
                f"  →  {rec.get('vulnerability')}"
                f"  CVSS: {_na(rec.get('cvss'), '.1f')}"
                f"  KEV: {_yn(rec.get('kev'))}"
                f"  Fix: {_fix(rec.get('fix_versions') or [])}"
            )
    else:
        lines.append("  (none)")

    lines += ["", f"🟡 TEMP MITIGATION  ({len(temp_mit)} items — CVSS ≥ 7.0, no patch):"]
    if temp_mit:
        for i, rec in enumerate(temp_mit[:30], 1):
            lines.append(
                f"  {i}. [{rec.get('project')}]  "
                f"{rec.get('component')} {_na(rec.get('version'))}"
                f"  →  {rec.get('vulnerability')}"
                f"  CVSS: {_na(rec.get('cvss'), '.1f')}"
                f"  CWE: {', '.join(rec.get('cwe') or []) or 'N/A'}"
            )
    else:
        lines.append("  (none)")

    lines += ["", f"🟢 MONITOR  ({len(monitor)} items — lower risk):"]
    for i, rec in enumerate(monitor[:20], 1):
        lines.append(
            f"  {i}. [{rec.get('project')}]  "
            f"{rec.get('component')} {_na(rec.get('version'))}"
            f"  →  {rec.get('vulnerability')}"
            f"  CVSS: {_na(rec.get('cvss'), '.1f')}"
        )
    if not monitor:
        lines.append("  (none)")
    return "\n".join(lines)


def format_explainability(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    project = _na(evidence[0].get("project") if evidence else None)
    lines: list[str] = [
        f"Project: {project}", "",
        "Data Completeness Overview:", _summary_block(summary), "",
        f"Vulnerability Detail ({min(len(evidence), 20)} records):",
    ]
    for i, rec in enumerate(evidence[:20], 1):
        missing: list[str] = []
        for field in ("cvss", "kev", "epss", "fix_versions", "location_path", "dependency_chain"):
            val = rec.get(field)
            if val is None or val == [] or val == "":
                missing.append(field)
        lines.append(_vuln_line(rec, i))
        if missing:
            lines.append(f"     ⚠ Missing data: {', '.join(missing)}")
    return "\n".join(lines)


def format_multi_audience(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    project = _na(evidence[0].get("project") if evidence else None)
    vuln_recs = [r for r in evidence if r.get("vulnerability")]
    reviewer_recs = [r for r in evidence if r.get("vulnerability") or r.get("component")]
    lines: list[str] = [
        f"Project: {project}", "",
        "=== Manager View ===",
        f"  Total vulnerability records : {summary.get('total_records', 0)}",
        f"  KEV (actively exploited)    : {summary.get('kev_count', 0)}",
        f"  With available fix          : {summary.get('has_fix_count', 0)}",
        f"  Without fix                 : {summary.get('no_fix_count', 0)}",
        f"  Max CVSS score              : {_na(summary.get('max_cvss'), '.1f')}",
        "", "=== Developer Guidance ===",
    ]
    if vuln_recs:
        for i, rec in enumerate(vuln_recs[:25], 1):
            lines.append(_vuln_line(rec, i))
    else:
        lines.append("  (No vulnerability data returned)")

    lines += ["", "=== Security Reviewer Log (full records) ==="]
    for i, rec in enumerate(reviewer_recs[:25], 1):
        missing = [
            f for f in ("cvss", "kev", "epss", "fix_versions", "location_path", "dependency_chain")
            if not rec.get(f) and rec.get(f) != 0
        ]
        lines.append(
            f"  [{i}] {rec.get('project')}  |  "
            f"{rec.get('component')} {_na(rec.get('version'))}  |  "
            f"{_na(rec.get('vulnerability'))}  |  "
            f"CVSS: {_na(rec.get('cvss'), '.1f')}  |  "
            f"KEV: {_yn(rec.get('kev'))}  |  "
            f"EPSS: {_na(rec.get('epss'), '.4f')}  |  "
            f"Fix: {_fix(rec.get('fix_versions') or [])}"
        )
        if missing:
            lines.append(f"       ⚠ Missing: {', '.join(missing)}")
    return "\n".join(lines)


def format_project_overview(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    if not evidence:
        return "No project data returned."
    rec   = evidence[0]
    proj  = _na(rec.get("project"))
    total = rec.get("total_vulns", 0)
    comps = rec.get("total_components", 0)
    crit  = rec.get("critical_high_count", 0)
    top   = rec.get("top_risks") or []
    lines: list[str] = [
        f"Project: {proj}", "",
        "Security Posture Snapshot:",
        f"  Total vulnerabilities  : {total}",
        f"  Total components       : {comps}",
        f"  Critical / High (≥7.0) : {crit}",
        "", "Top 10 Risks (ordered by KEV then CVSS):",
    ]
    for i, item in enumerate(top[:10], 1):
        if isinstance(item, dict):
            v_id = item.get("vulnerability") or "N/A"
            comp = item.get("component") or "N/A"
            cvss = _na(item.get("cvss"), ".1f")
            kev  = _yn(item.get("kev"))
            lines.append(f"  {i:>2}. {comp}  →  {v_id}  CVSS: {cvss}  KEV: {kev}")
        else:
            lines.append(f"  {i:>2}. {item}")
    return "\n".join(lines)


def format_arch_impact(evidence: list[EvidenceRecord], summary: dict[str, Any]) -> str:
    if not evidence:
        return "No architectural impact data available."
    lines: list[str] = [
        "Blast Radius Analysis", "=" * 50, "",
        "Overview:", _summary_block(summary), "",
        f"Affected Paths ({min(len(evidence), 30)} shown):",
    ]
    for i, rec in enumerate(evidence[:30], 1):
        vuln  = _na(rec.get("vulnerability"))
        comp  = _na(rec.get("component"))
        ver   = _na(rec.get("version"))
        chain = _dep_chain(rec)
        depth = _na(rec.get("depth"))
        loc   = _location_line(rec)
        semgrep_verdict = rec.get("reachability_verdict")
        semgrep_locs = rec.get("semgrep_call_locations") or []
        semgrep_sinks = rec.get("semgrep_sink_functions") or []
        lines.append(f"  {i}. {comp} {ver}  →  {vuln}")
        if depth != "N/A":
            lines.append(f"     Depth: {depth} hops")
        if loc:
            lines.append(f"     EntryPoint: {loc}")
        if chain:
            lines.append(f"     Path: {chain}")
        if semgrep_verdict:
            lines.append(
                "     Semgrep: "
                f"verdict={semgrep_verdict}"
                f" | sinks={len(semgrep_sinks)}"
                f" | call_locations={len(semgrep_locs)}"
            )
            if semgrep_locs:
                lines.append(f"     Calls: {', '.join(semgrep_locs[:3])}")
    return "\n".join(lines)
