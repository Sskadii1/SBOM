"""
modules/agents/sink_db.py - SQLite knowledge base for CVE sink data.

Schema:
  cve_advisories   — raw advisory text cache (avoid re-fetching)
  cve_sinks        — extracted sink functions per CVE/package
  reachability_results — Semgrep scan results per project
"""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "cve_sinks.db"


def get_db_path() -> Path:
    import os
    return Path(os.environ.get("CVE_SINKS_DB", str(_DEFAULT_DB)))


@contextmanager
def _conn(db_path: Optional[Path] = None):
    path = db_path or get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS cve_advisories (
    vuln_id     TEXT PRIMARY KEY,
    summary     TEXT,
    cwe         TEXT,
    aliases     TEXT,          -- JSON array
    fetched_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cve_sinks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id         TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    ecosystem       TEXT,
    function_name   TEXT,
    class_name      TEXT,
    call_pattern    TEXT,      -- Semgrep pattern string
    sink_type       TEXT,      -- function_call | method_call | constructor
    vuln_type       TEXT,
    confidence      REAL DEFAULT 0.7,
    source          TEXT DEFAULT 'ai',   -- ai | heuristic | manual
    raw_evidence    TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(vuln_id, package_name, function_name)
);

CREATE TABLE IF NOT EXISTS reachability_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name    TEXT NOT NULL,
    vuln_id         TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    sink_function   TEXT,
    verdict         TEXT NOT NULL,
    reach_score     REAL,
    call_locations  TEXT,      -- JSON array of "file:line"
    semgrep_rule_id TEXT,
    scanned_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(project_name, vuln_id, sink_function)
);

CREATE INDEX IF NOT EXISTS idx_sinks_vuln  ON cve_sinks(vuln_id);
CREATE INDEX IF NOT EXISTS idx_sinks_pkg   ON cve_sinks(package_name);
CREATE INDEX IF NOT EXISTS idx_reach_proj  ON reachability_results(project_name);
CREATE INDEX IF NOT EXISTS idx_reach_vuln  ON reachability_results(project_name, vuln_id);
"""


def init_db(db_path: Optional[Path] = None) -> None:
    with _conn(db_path) as con:
        con.executescript(_DDL)


# ---------------------------------------------------------------------------
# Sink read/write
# ---------------------------------------------------------------------------

def get_sinks(vuln_id: str, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return all sinks for a vuln_id."""
    with _conn(db_path) as con:
        rows = con.execute(
            "SELECT * FROM cve_sinks WHERE vuln_id = ?", (vuln_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_sinks_for_vulns(vuln_ids: List[str], db_path: Optional[Path] = None) -> Dict[str, List[Dict]]:
    """Return {vuln_id: [sink, ...]} for a batch of vuln_ids."""
    if not vuln_ids:
        return {}
    placeholders = ",".join("?" * len(vuln_ids))
    with _conn(db_path) as con:
        rows = con.execute(
            f"SELECT * FROM cve_sinks WHERE vuln_id IN ({placeholders})",  # nosec B608
            vuln_ids,
        ).fetchall()
    result: Dict[str, List[Dict]] = {v: [] for v in vuln_ids}
    for r in rows:
        result[r["vuln_id"]].append(dict(r))
    return result


def insert_sinks(sinks: List[Dict[str, Any]], db_path: Optional[Path] = None) -> int:
    """
    Insert sinks, ignore conflicts (UNIQUE on vuln_id+package+function).
    Returns number of rows actually inserted.
    """
    if not sinks:
        return 0
    cols = [
        "vuln_id", "package_name", "ecosystem", "function_name", "class_name",
        "call_pattern", "sink_type", "vuln_type", "confidence", "source", "raw_evidence",
    ]
    placeholders = ",".join("?" * len(cols))
    col_str = ",".join(cols)
    inserted = 0
    with _conn(db_path) as con:
        for s in sinks:
            values = [s.get(c) for c in cols]
            cur = con.execute(
                f"INSERT OR IGNORE INTO cve_sinks ({col_str}) VALUES ({placeholders})",
                values,
            )
            inserted += cur.rowcount
    return inserted


def has_sinks(vuln_id: str, db_path: Optional[Path] = None) -> bool:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT 1 FROM cve_sinks WHERE vuln_id = ? LIMIT 1", (vuln_id,)
        ).fetchone()
        return row is not None


def missing_vulns(vuln_ids: List[str], db_path: Optional[Path] = None) -> List[str]:
    """Return vuln_ids that have no sinks in the DB yet."""
    if not vuln_ids:
        return []
    placeholders = ",".join("?" * len(vuln_ids))
    with _conn(db_path) as con:
        rows = con.execute(
            f"SELECT DISTINCT vuln_id FROM cve_sinks WHERE vuln_id IN ({placeholders})",  # nosec B608
            vuln_ids,
        ).fetchall()
    have = {r["vuln_id"] for r in rows}
    return [v for v in vuln_ids if v not in have]


# ---------------------------------------------------------------------------
# Advisory cache
# ---------------------------------------------------------------------------

def cache_advisory(vuln_id: str, summary: str, cwe: str,
                   aliases: List[str], db_path: Optional[Path] = None) -> None:
    with _conn(db_path) as con:
        con.execute(
            """INSERT OR REPLACE INTO cve_advisories (vuln_id, summary, cwe, aliases)
               VALUES (?, ?, ?, ?)""",
            (vuln_id, summary, cwe, json.dumps(aliases or [])),
        )


# ---------------------------------------------------------------------------
# Reachability read/write
# ---------------------------------------------------------------------------

def save_reachability(project_name: str, results: List[Dict[str, Any]],
                      db_path: Optional[Path] = None) -> int:
    """Upsert reachability results for a project."""
    if not results:
        return 0
    cols = [
        "project_name", "vuln_id", "package_name", "sink_function",
        "verdict", "reach_score", "call_locations", "semgrep_rule_id",
    ]
    placeholders = ",".join("?" * len(cols))
    col_str = ",".join(cols)
    saved = 0
    with _conn(db_path) as con:
        for r in results:
            locs = r.get("call_locations", [])
            values = [
                project_name,
                r.get("vuln_id", ""),
                r.get("package_name", ""),
                r.get("sink_function"),
                r.get("verdict", "no_sink_data"),
                r.get("reach_score"),
                json.dumps(locs) if isinstance(locs, list) else locs,
                r.get("semgrep_rule_id"),
            ]
            con.execute(
                f"""INSERT OR REPLACE INTO reachability_results ({col_str})
                    VALUES ({placeholders})""",
                values,
            )
            saved += 1
    return saved


def get_reachability(project_name: str, vuln_ids: Optional[List[str]] = None,
                     db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load reachability results for a project, optionally filtered by vuln_ids."""
    with _conn(db_path) as con:
        if vuln_ids:
            placeholders = ",".join("?" * len(vuln_ids))
            rows = con.execute(
                f"SELECT * FROM reachability_results WHERE project_name=? "  # nosec B608
                f"AND vuln_id IN ({placeholders})",
                [project_name] + vuln_ids,
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM reachability_results WHERE project_name=?",
                (project_name,),
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("call_locations"), str):
                try:
                    d["call_locations"] = json.loads(d["call_locations"])
                except Exception:
                    pass
            results.append(d)
        return results


def load_ai_json_output(json_path: Path, db_path: Optional[Path] = None) -> Dict[str, int]:
    """
    Parse AI output JSON (array of {vuln_id, package, ecosystem, sinks:[...]})
    and insert into cve_sinks. Returns {"inserted": N, "skipped": M}.
    """
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Expected a JSON array at top level")

    all_sinks = []
    for entry in data:
        vuln_id = entry.get("vuln_id", "")
        pkg = entry.get("package", "")
        eco = entry.get("ecosystem", "")
        for sink in entry.get("sinks", []):
            all_sinks.append({
                "vuln_id": vuln_id,
                "package_name": pkg,
                "ecosystem": eco,
                "function_name": sink.get("function_name"),
                "class_name": sink.get("class_name"),
                "call_pattern": sink.get("call_pattern"),
                "sink_type": sink.get("sink_type", "function_call"),
                "vuln_type": sink.get("vuln_type", "Unknown"),
                "confidence": float(sink.get("confidence", 0.7)),
                "source": "ai",
                "raw_evidence": sink.get("note", ""),
            })

    inserted = insert_sinks(all_sinks, db_path)
    skipped = len(all_sinks) - inserted
    return {"inserted": inserted, "skipped": skipped, "total": len(all_sinks)}
