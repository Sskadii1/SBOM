"""
tune_risk_weights.py — Adjust Risk Score weights and apply to all source files.

USAGE:
    1. Edit the values in the CONFIG section below.
    2. Run:  python tune_risk_weights.py
       or:   python tune_risk_weights.py --dry-run   (preview only, no writes)

FILES PATCHED:
    - gui_retrieval/backend/repositories/graph_repository.py
    - gui_retrieval/frontend/views/alerts.py
"""

import argparse
import sys
from pathlib import Path

# ===========================================================================
# CONFIG — Edit these values to tune the risk score formula
# ===========================================================================
#
#  Formula:  Risk = 100 × (W_SEV×S_sev + W_EXP×S_exp + W_SCOPE×S_scope + W_REACH×S_reach)
#  Weights must sum to 1.0
#
W_SEV   = 0.25   # S_sev   — CVSS severity   (0–1)
W_EXP   = 0.25   # S_exp   — Exploitability  (KEV=1.0, else EPSS)
W_SCOPE = 0.15   # S_scope — Dependency scope
W_REACH = 0.35   # S_reach — Reachability

# Scope sub-scores
SCOPE_RUNTIME  = 1.0   # required / runtime
SCOPE_DEFAULT  = 0.6   # unknown / other
SCOPE_DEV      = 0.3   # optional / dev / test

# Reachability sub-scores (verdict → score)
REACH_CONFIRMED  = 1.0   # confirmed_reachable
REACH_LIKELY     = 0.7   # likely_reachable
REACH_UNLIKELY   = 0.3   # likely_unreachable
REACH_NO_DATA    = 0.5   # no_sink_data

# Risk score thresholds (out of 100)
THRESH_CRITICAL = 85
THRESH_HIGH     = 70
THRESH_MEDIUM   = 40

# ===========================================================================
# END CONFIG
# ===========================================================================


def _fmt(v: float) -> str:
    """Format float with up to 2 decimal places, stripping trailing zeros."""
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return s if "." in s or s == "0" else s


def _validate() -> list[str]:
    errors = []
    total = W_SEV + W_EXP + W_SCOPE + W_REACH
    if abs(total - 1.0) > 1e-9:
        errors.append(f"Weights do not sum to 1.0 (got {total:.4f}). Adjust W_SEV/W_EXP/W_SCOPE/W_REACH.")
    for name, val in [("SCOPE_RUNTIME", SCOPE_RUNTIME), ("SCOPE_DEFAULT", SCOPE_DEFAULT),
                      ("SCOPE_DEV", SCOPE_DEV), ("REACH_CONFIRMED", REACH_CONFIRMED),
                      ("REACH_LIKELY", REACH_LIKELY), ("REACH_UNLIKELY", REACH_UNLIKELY),
                      ("REACH_NO_DATA", REACH_NO_DATA)]:
        if not (0.0 <= val <= 1.0):
            errors.append(f"{name} = {val} is out of range [0, 1].")
    if not (0 < THRESH_MEDIUM < THRESH_HIGH < THRESH_CRITICAL <= 100):
        errors.append("Thresholds must satisfy: 0 < THRESH_MEDIUM < THRESH_HIGH < THRESH_CRITICAL <= 100")
    return errors


def _patches_graph_repository() -> list[tuple[str, str, str]]:
    """Return list of (description, old_string, new_string) for graph_repository.py."""
    w_sev   = _fmt(W_SEV)
    w_exp   = _fmt(W_EXP)
    w_scope = _fmt(W_SCOPE)
    w_reach = _fmt(W_REACH)
    sr = _fmt(SCOPE_RUNTIME)
    sd = _fmt(SCOPE_DEFAULT)
    sdev = _fmt(SCOPE_DEV)
    rc = _fmt(REACH_CONFIRMED)
    rl = _fmt(REACH_LIKELY)
    ru = _fmt(REACH_UNLIKELY)
    rn = _fmt(REACH_NO_DATA)

    patches = []

    # ---- 1. Cypher query: _CYPHER_ALL_ALERTS (collect scope variant) ----
    patches.append((
        "Cypher _CYPHER_ALL_ALERTS weights",
        (
            "      0.25 * coalesce(max(v.cvss_score), 0) / 10.0\n"
            "      + 0.25 * CASE\n"
            "                 WHEN max(v.kev) = true THEN 1.0\n"
            "                 ELSE coalesce(max(v.epss), 0)\n"
            "               END\n"
            "      + 0.15 * CASE\n"
            "                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['required', 'runtime']) THEN 1.0\n"
            "                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['optional', 'dev', 'test']) THEN 0.3\n"
            "                 ELSE 0.6\n"
            "               END\n"
            "      + 0.35 * 0.5"
        ),
        (
            f"      {w_sev} * coalesce(max(v.cvss_score), 0) / 10.0\n"
            f"      + {w_exp} * CASE\n"
            "                 WHEN max(v.kev) = true THEN 1.0\n"
            "                 ELSE coalesce(max(v.epss), 0)\n"
            "               END\n"
            f"      + {w_scope} * CASE\n"
            f"                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['required', 'runtime']) THEN {sr}\n"
            f"                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['optional', 'dev', 'test']) THEN {sdev}\n"
            f"                 ELSE {sd}\n"
            "               END\n"
            f"      + {w_reach} * {rn}"
        ),
    ))

    # ---- 2. Cypher query: _CYPHER_VULN_DETAIL (single scope variant) ----
    patches.append((
        "Cypher _CYPHER_VULN_DETAIL weights",
        (
            "      0.25 * coalesce(max(v.cvss_score), 0) / 10.0\n"
            "      + 0.25 * CASE\n"
            "                 WHEN max(v.kev) = true THEN 1.0\n"
            "                 ELSE coalesce(max(v.epss), 0)\n"
            "               END\n"
            "      + 0.15 * CASE\n"
            "                 WHEN c.scope IN ['required', 'runtime'] THEN 1.0\n"
            "                 WHEN c.scope IN ['optional', 'dev', 'test'] THEN 0.3\n"
            "                 ELSE 0.6\n"
            "               END\n"
            "      + 0.35 * 0.5"
        ),
        (
            f"      {w_sev} * coalesce(max(v.cvss_score), 0) / 10.0\n"
            f"      + {w_exp} * CASE\n"
            "                 WHEN max(v.kev) = true THEN 1.0\n"
            "                 ELSE coalesce(max(v.epss), 0)\n"
            "               END\n"
            f"      + {w_scope} * CASE\n"
            f"                 WHEN c.scope IN ['required', 'runtime'] THEN {sr}\n"
            f"                 WHEN c.scope IN ['optional', 'dev', 'test'] THEN {sdev}\n"
            f"                 ELSE {sd}\n"
            "               END\n"
            f"      + {w_reach} * {rn}"
        ),
    ))

    # ---- 3. _reachability_factor mapping ----
    patches.append((
        "_reachability_factor mapping",
        (
            '    mapping = {\n'
            '        "confirmed_reachable": 1.0,\n'
            '        "likely_reachable": 0.7,\n'
            '        "likely_unreachable": 0.3,\n'
            '        "no_sink_data": 0.5,\n'
            '    }'
        ),
        (
            '    mapping = {\n'
            f'        "confirmed_reachable": {rc},\n'
            f'        "likely_reachable": {rl},\n'
            f'        "likely_unreachable": {ru},\n'
            f'        "no_sink_data": {rn},\n'
            '    }'
        ),
    ))

    # ---- 4. _recompute_risk return statement ----
    patches.append((
        "_recompute_risk formula weights",
        (
            "    return round(100.0 * (\n"
            "        0.25 * s_sev +\n"
            "        0.25 * s_exp +\n"
            "        0.15 * s_scope +\n"
            "        0.35 * reach_factor\n"
            "    ), 2)"
        ),
        (
            "    return round(100.0 * (\n"
            f"        {w_sev} * s_sev +\n"
            f"        {w_exp} * s_exp +\n"
            f"        {w_scope} * s_scope +\n"
            f"        {w_reach} * reach_factor\n"
            "    ), 2)"
        ),
    ))

    return patches


def _patches_alerts() -> list[tuple[str, str, str]]:
    """Return list of (description, old_string, new_string) for alerts.py."""
    w_sev   = _fmt(W_SEV)
    w_exp   = _fmt(W_EXP)
    w_scope = _fmt(W_SCOPE)
    w_reach = _fmt(W_REACH)
    rc = _fmt(REACH_CONFIRMED)
    rl = _fmt(REACH_LIKELY)
    ru = _fmt(REACH_UNLIKELY)
    rn = _fmt(REACH_NO_DATA)
    tc = THRESH_CRITICAL
    th = THRESH_HIGH
    tm = THRESH_MEDIUM

    patches = []

    # ---- 1. Reachability factor mapping in detail view ----
    patches.append((
        "alerts.py reachability_factor mapping",
        (
            '        first["reachability_factor"] = {\n'
            '            "confirmed_reachable": 1.0,\n'
            '            "likely_reachable": 0.7,\n'
            '            "likely_unreachable": 0.3,\n'
            '            "no_sink_data": 0.5,\n'
            '        }.get(first["reachability_verdict"], 0.5)'
        ),
        (
            '        first["reachability_factor"] = {\n'
            f'            "confirmed_reachable": {rc},\n'
            f'            "likely_reachable": {rl},\n'
            f'            "likely_unreachable": {ru},\n'
            f'            "no_sink_data": {rn},\n'
            f'        }}.get(first["reachability_verdict"], {rn})'
        ),
    ))

    # ---- 2. weighted_sum formula ----
    patches.append((
        "alerts.py weighted_sum formula",
        "    weighted_sum = 0.25 * s_sev + 0.25 * s_exp + 0.15 * s_scope + 0.35 * u_val",
        f"    weighted_sum = {w_sev} * s_sev + {w_exp} * s_exp + {w_scope} * s_scope + {w_reach} * u_val",
    ))

    # ---- 3. _param_row calls with weights ----
    patches.append((
        "alerts.py _param_row weight arguments",
        (
            '        _param_row("S_sev", f"CVSS = {_rs_cvss:.1f} &rarr; {_rs_cvss:.1f}/10", s_sev, 0.25)\n'
            '        + _param_row("S_exp", f"KEV = {\'Yes &rarr; 1.0\' if _rs_kev else \'No &rarr; EPSS = \' + f\'{_rs_epss:.4f}\'}", s_exp, 0.25)\n'
            '        + _param_row("S_scope", f"scope = {scope_display} &rarr; {s_scope:.1f}", s_scope, 0.15)\n'
            '        + _param_row("S_reach", f"{_reach_label} &rarr; {u_val:.1f}", u_val, 0.35)'
        ),
        (
            f'        _param_row("S_sev", f"CVSS = {{_rs_cvss:.1f}} &rarr; {{_rs_cvss:.1f}}/10", s_sev, {w_sev})\n'
            f'        + _param_row("S_exp", f"KEV = {{\'Yes &rarr; 1.0\' if _rs_kev else \'No &rarr; EPSS = \' + f\'{{_rs_epss:.4f}}\'  }}", s_exp, {w_exp})\n'
            f'        + _param_row("S_scope", f"scope = {{scope_display}} &rarr; {{s_scope:.1f}}", s_scope, {w_scope})\n'
            f'        + _param_row("S_reach", f"{{_reach_label}} &rarr; {{u_val:.1f}}", u_val, {w_reach})'
        ),
    ))

    # ---- 4. Formula display string ----
    patches.append((
        "alerts.py formula display string",
        (
            "        f'Risk<sub>enh</sub> = 100 &times; (0.25&times;S_sev + 0.25&times;S_exp + 0.15&times;S_scope + 0.35&times;S_reach)'"
        ),
        (
            f"        f'Risk<sub>enh</sub> = 100 &times; ({w_sev}&times;S_sev + {w_exp}&times;S_exp + {w_scope}&times;S_scope + {w_reach}&times;S_reach)'"
        ),
    ))

    # ---- 5. Risk thresholds — detail view ----
    patches.append((
        "alerts.py risk thresholds (detail view)",
        (
            "    if computed_risk >= 85:\n"
            '        rs_color = "#cf222e"; rs_bg = "#FFEBE9"; rs_label = "Critical"\n'
            "    elif computed_risk >= 70:\n"
            '        rs_color = "#bc4c00"; rs_bg = "#FFF8C5"; rs_label = "High"\n'
            "    elif computed_risk >= 40:\n"
            '        rs_color = "#9a6700"; rs_bg = "#FFF8C5"; rs_label = "Medium"'
        ),
        (
            f"    if computed_risk >= {tc}:\n"
            '        rs_color = "#cf222e"; rs_bg = "#FFEBE9"; rs_label = "Critical"\n'
            f"    elif computed_risk >= {th}:\n"
            '        rs_color = "#bc4c00"; rs_bg = "#FFF8C5"; rs_label = "High"\n'
            f"    elif computed_risk >= {tm}:\n"
            '        rs_color = "#9a6700"; rs_bg = "#FFF8C5"; rs_label = "Medium"'
        ),
    ))

    # ---- 6. Risk thresholds — list view (badge coloring) ----
    patches.append((
        "alerts.py risk thresholds (list badge)",
        (
            "        if risk_score >= 85:\n"
            '            risk_color = "#cf222e"; risk_bg = "#FFEBE9"\n'
            "        elif risk_score >= 70:\n"
            '            risk_color = "#bc4c00"; risk_bg = "#FFF8C5"\n'
            "        elif risk_score >= 40:\n"
            '            risk_color = "#9a6700"; risk_bg = "#FFF8C5"'
        ),
        (
            f"        if risk_score >= {tc}:\n"
            '            risk_color = "#cf222e"; risk_bg = "#FFEBE9"\n'
            f"        elif risk_score >= {th}:\n"
            '            risk_color = "#bc4c00"; risk_bg = "#FFF8C5"\n'
            f"        elif risk_score >= {tm}:\n"
            '            risk_color = "#9a6700"; risk_bg = "#FFF8C5"'
        ),
    ))

    return patches


def _apply_patches(
    file_path: Path,
    patches: list[tuple[str, str, str]],
    dry_run: bool,
) -> tuple[int, int]:
    """Apply patches to a file. Returns (applied, failed) counts."""
    content = file_path.read_text(encoding="utf-8")
    applied = 0
    failed = 0

    for desc, old, new in patches:
        if old == new:
            print(f"  [skip]   {desc} — no change needed")
            continue
        if old in content:
            content = content.replace(old, new, 1)
            print(f"  [ok]     {desc}")
            applied += 1
        else:
            print(f"  [MISS]   {desc} — pattern not found in file")
            failed += 1

    if not dry_run and applied > 0:
        file_path.write_text(content, encoding="utf-8")

    return applied, failed


def main() -> None:
    parser = argparse.ArgumentParser(description="Tune risk score weights across source files.")
    parser.add_argument("--dry-run", action="store_true", help="Preview patches without writing files")
    args = parser.parse_args()

    # Validate config
    errors = _validate()
    if errors:
        print("CONFIG ERRORS — fix before applying:")
        for e in errors:
            print(f"  x {e}")
        sys.exit(1)

    print(f"\nRisk formula: 100 x ({W_SEV}*S_sev + {W_EXP}*S_exp + {W_SCOPE}*S_scope + {W_REACH}*S_reach)")
    print(f"Reachability: confirmed={REACH_CONFIRMED}, likely={REACH_LIKELY}, unlikely={REACH_UNLIKELY}, no_data={REACH_NO_DATA}")
    print(f"Thresholds:   critical>={THRESH_CRITICAL}, high>={THRESH_HIGH}, medium>={THRESH_MEDIUM}")
    if args.dry_run:
        print("** DRY RUN — no files will be written **")
    print()

    root = Path(__file__).parent
    targets = [
        (root / "gui_retrieval" / "backend" / "repositories" / "graph_repository.py",
         _patches_graph_repository()),
        (root / "gui_retrieval" / "frontend" / "views" / "alerts.py",
         _patches_alerts()),
    ]

    total_applied = 0
    total_failed = 0
    for file_path, patches in targets:
        print(f"--- {file_path.relative_to(root)} ---")
        if not file_path.exists():
            print(f"  [ERROR] File not found: {file_path}")
            total_failed += len(patches)
            continue
        applied, failed = _apply_patches(file_path, patches, dry_run=args.dry_run)
        total_applied += applied
        total_failed += failed
        print()

    print(f"Done: {total_applied} patch(es) applied, {total_failed} missed.")
    if total_failed:
        print("Missed patches mean the source file has changed — update tune_risk_weights.py manually.")
    if args.dry_run and total_applied:
        print("Run without --dry-run to write changes.")


if __name__ == "__main__":
    main()
