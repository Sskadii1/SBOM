"""
Lightweight SQLite persistence for alert case state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import uuid
from typing import Any

import backend.config as config
from backend.models import (
    DEFAULT_CASE_STATUS,
    DEFAULT_DECISION_TIER,
    AlertCase,
    CaseStatus,
    DecisionTier,
    normalize_case_status,
    normalize_decision_tier,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path() -> Path:
    return Path(config.CVE_SINKS_DB)


def _normalize_component_id(component_id: str | None) -> str:
    return (component_id or "").strip()


def _none_if_empty(value: str) -> str | None:
    stripped = value.strip()
    return stripped if stripped else None


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    return con


def _recreate_case_state_table(con: sqlite3.Connection) -> None:
    con.execute("ALTER TABLE case_state RENAME TO case_state_legacy")
    con.execute(
        """
        CREATE TABLE case_state (
            project TEXT NOT NULL,
            vuln_id TEXT NOT NULL,
            component_id TEXT NOT NULL DEFAULT '',
            decision_tier TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (project, vuln_id, component_id)
        )
        """
    )
    con.execute(
        """
        INSERT INTO case_state (
            project,
            vuln_id,
            component_id,
            decision_tier,
            status,
            updated_at
        )
        SELECT
            project,
            vuln_id,
            component_id,
            decision_tier,
            status,
            updated_at
        FROM case_state_legacy
        """
    )
    con.execute("DROP TABLE case_state_legacy")


def _ensure_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS case_state (
            project TEXT NOT NULL,
            vuln_id TEXT NOT NULL,
            component_id TEXT NOT NULL DEFAULT '',
            decision_tier TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (project, vuln_id, component_id)
        )
        """
    )
    columns = [
        row["name"]
        for row in con.execute("PRAGMA table_info(case_state)").fetchall()
    ]
    expected_columns = [
        "project",
        "vuln_id",
        "component_id",
        "decision_tier",
        "status",
        "updated_at",
    ]
    if columns != expected_columns:
        _recreate_case_state_table(con)
    con.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_state_project
            ON case_state(project)
        """
    )
    con.commit()


def init_case_state_tables() -> None:
    """Ensure persistence tables exist."""
    with _connect() as con:
        _ensure_tables(con)


def _row_to_case_state(row: sqlite3.Row) -> dict[str, Any]:
    component_id = _none_if_empty(str(row["component_id"] or ""))
    decision_tier = normalize_decision_tier(
        row["decision_tier"],
        default=DEFAULT_DECISION_TIER,
    )
    status = normalize_case_status(
        row["status"],
        default=DEFAULT_CASE_STATUS,
    )
    return {
        "project": str(row["project"]),
        "vuln_id": str(row["vuln_id"]),
        "component_id": component_id,
        "decision_tier": decision_tier,
        "status": status,
        "updated_at": row["updated_at"],
    }


def get_case_states(project: str) -> dict[tuple[str, str, str | None], dict[str, Any]]:
    """
    Return all persisted case states keyed by (project, vuln_id, component_id).
    """
    with _connect() as con:
        _ensure_tables(con)
        rows = con.execute(
            """
            SELECT
              project,
              vuln_id,
              component_id,
              decision_tier,
              status,
              updated_at
            FROM case_state
            WHERE project = ?
            """,
            (project,),
        ).fetchall()

    state_map: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for row in rows:
        state = _row_to_case_state(row)
        key = (state["project"], state["vuln_id"], state["component_id"])
        state_map[key] = state
    return state_map


def get_case_state(
    project: str,
    vuln_id: str,
    component_id: str | None = None,
) -> dict[str, Any] | None:
    with _connect() as con:
        _ensure_tables(con)
        row = con.execute(
            """
            SELECT
              project,
              vuln_id,
              component_id,
              decision_tier,
              status,
              updated_at
            FROM case_state
            WHERE project = ?
              AND vuln_id = ?
              AND component_id = ?
            LIMIT 1
            """,
            (project, vuln_id, _normalize_component_id(component_id)),
        ).fetchone()
    if not row:
        return None
    return _row_to_case_state(row)


def upsert_case_state(
    project: str,
    vuln_id: str,
    component_id: str | None = None,
    *,
    decision_tier: DecisionTier | str | None = None,
    status: CaseStatus | str | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """
    Insert or update one case-state row and return the persisted row.
    """
    existing = get_case_state(project, vuln_id, component_id)

    resolved_decision_tier = normalize_decision_tier(
        decision_tier if decision_tier is not None else (existing or {}).get("decision_tier"),
        default=DEFAULT_DECISION_TIER,
    )
    resolved_status = normalize_case_status(
        status if status is not None else (existing or {}).get("status"),
        default=DEFAULT_CASE_STATUS,
    )
    resolved_updated_at = updated_at or _utc_now_iso()

    with _connect() as con:
        _ensure_tables(con)
        con.execute(
            """
            INSERT INTO case_state (
              project,
              vuln_id,
              component_id,
              decision_tier,
              status,
              updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project, vuln_id, component_id)
            DO UPDATE SET
              decision_tier = excluded.decision_tier,
              status = excluded.status,
              updated_at = excluded.updated_at
            """,
            (
                project,
                vuln_id,
                _normalize_component_id(component_id),
                resolved_decision_tier,
                resolved_status,
                resolved_updated_at,
            ),
        )
        con.commit()

    row = get_case_state(project, vuln_id, component_id)
    if row is None:
        raise RuntimeError("Failed to persist case state.")
    return row


def bootstrap_default_states(project: str, alert_cases: list[AlertCase]) -> int:
    """
    Ensure each alert case has a persisted state row; existing rows are preserved.
    Returns number of inserted rows.
    """
    if not alert_cases:
        return 0

    inserted = 0
    now = _utc_now_iso()
    with _connect() as con:
        _ensure_tables(con)
        for case in alert_cases:
            cursor = con.execute(
                """
                INSERT OR IGNORE INTO case_state (
                  project,
                  vuln_id,
                  component_id,
                  decision_tier,
                  status,
                  updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    project,
                    case["vuln_id"],
                    _normalize_component_id(case.get("component_id")),
                    normalize_decision_tier(
                        case.get("decision_tier"),
                        default=DEFAULT_DECISION_TIER,
                    ),
                    normalize_case_status(
                        case.get("status"),
                        default=DEFAULT_CASE_STATUS,
                    ),
                    now,
                ),
            )
            inserted += int(cursor.rowcount > 0)
        con.commit()
    return inserted


def record_report_run(
    project: str,
    *,
    generated_at: str | None = None,
    sbom_source: str | None = None,
    reachability_source: str | None = None,
    vulnerability_source: str | None = None,
    report_version: str | None = None,
    run_id: str | None = None,
) -> str:
    """
    Deprecated no-op: run metadata persistence has been removed.
    Returns a generated run id to preserve call-site compatibility.
    """
    resolved_run_id = run_id or f"run_{uuid.uuid4().hex}"
    return resolved_run_id


def get_latest_report_run(project: str) -> dict[str, Any] | None:
    _ = project
    return None


def get_recent_report_runs(project: str, limit: int = 10) -> list[dict[str, Any]]:
    _ = (project, limit)
    return []


def record_report_case_snapshot(
    project: str,
    run_id: str,
    alert_cases: list[AlertCase],
) -> int:
    """
    Deprecated no-op: report snapshot persistence has been removed.
    """
    _ = (project, run_id, alert_cases)
    return 0


def get_report_case_snapshot(run_id: str) -> list[dict[str, Any]]:
    """
    Deprecated no-op: report snapshot persistence has been removed.
    """
    _ = run_id
    return []
