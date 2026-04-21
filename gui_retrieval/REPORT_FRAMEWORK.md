# Report Framework Overview

This document summarizes the report-centric retrieval/output framework in
`gui_retrieval`.

## Goal

Shift from scenario-centric GraphRAG demos to two stable product outputs:

1. Stakeholder Security Posture Report
2. Developer Vulnerability Remediation Report

## Core Layers

### 1. Canonical models

`backend/models/` defines shared contracts:

- `AlertCase`
- `StakeholderReport`
- `DeveloperReport`
- statuses and decision tiers

### 2. Evidence normalization

`backend/services/evidence_service.py` converts heterogeneous Neo4j rows into
canonical `AlertCase` objects.

### 3. Case state + report metadata persistence

`backend/services/case_state_service.py` stores:

- `case_state`: decision/status ownership lifecycle
- `report_run`: report generation metadata
- `report_case_snapshot`: compact run snapshots for comparison

### 4. Report builders

`backend/services/stakeholder_report_builder.py` and
`backend/services/developer_report_builder.py` generate schema-complete report
objects without requiring LLM.

### 5. Orchestration

`backend/services/report_service.py` coordinates data retrieval, case-state
overrides, snapshot recording, and optional LLM narrative augmentation.

### 6. Verification loop

`backend/services/verification_service.py` provides:

- `build_verification_delta(old_cases, new_cases)`
- `compare_current_vs_previous_report(project_name)`

Comparison focuses on:

- risk score delta
- reachability verdict shifts
- fix availability shifts

## Decision Tier Logic

Default `decision_tier` is computed from core signals in this order:

1. `fix_now`:
   - KEV + `confirmed_reachable`, or
   - risk score >= 80 with `confirmed_reachable` / `likely_reachable`
2. `plan_remediation`:
   - risk score >= 65 and fix version exists
3. `mitigate`:
   - reachable/likely reachable but no known fix version
4. `monitor`:
   - fallback for lower-confidence or lower-urgency cases

Manual overrides from `case_state` always take precedence over default tiering.

## Risk Register Lifecycle

Each risk-register row carries:

- `status` (workflow state)
- `lifecycle_state`:
  - `open`
  - `pending_verification` (`resolved_pending_verify`)
  - `closed` (`verified_closed`)
- `closed` boolean flag

Behavior:

- `top_risks` excludes `closed` items to keep stakeholder focus on active risk.
- `recommended_actions` only targets active (`open` + `pending_verification`) items.
- `closure_summary` tracks:
  - `verified_closed`
  - `resolved_pending_verify`
  - `still_open`
  - `open_without_owner`

## Stakeholder PDF Export

Stakeholder view supports PDF export via `backend/services/report_export_service.py`.
The PDF includes posture summary, narrative, top risks, recommended actions,
closure summary, and risk register snapshot.

## UI Mapping

Repository view presents:

- `Security Alerts`
- `Stakeholder Report`
- `Developer Report`

Legacy scenario analysis is preserved under internal/debug expanders.

## LLM Role

LLM is an augmentation layer only:

- reports remain valid if LLM is disabled/unavailable
- LLM writes prose/narrative over an existing deterministic report object
