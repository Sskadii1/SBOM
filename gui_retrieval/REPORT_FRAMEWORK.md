# Report Framework Overview

This document summarizes the report-centric retrieval/output framework in
`gui_retrieval`.

## Goal

Shift from scenario-centric GraphRAG demos to two stable product outputs:

1. Stakeholder Security Posture Report
2. Developer Vulnerability Remediation Report

The active framework is report-centric and grounded in:

1. `NIST SP 800-161r1` for SBOM and supply-chain risk context
2. `NIST SP 800-40 Rev.4` for remediation and verification workflow
3. `SSVC-lite` for action-tier prioritization

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

### 3. Identity and persistence

`Project` is the logical repository identity.
`SBOM` is the scan/snapshot identity and carries:

- `scan_id`
- `generated_at`
- `source_commit`
- `branch`

SQLite persistence stores:

- `case_state`: owner/status/tier plus last-seen and last-verified metadata
- `report_run`: report-to-scan lineage
- `report_case_snapshot`: baseline data for verification deltas

### 4. Case state persistence

`backend/services/case_state_service.py` stores lightweight operational state and
report-run snapshots without adding new infrastructure.

### 5. Report builders

`backend/services/stakeholder_report_builder.py` and
`backend/services/developer_report_builder.py` generate schema-complete report
objects without requiring LLM.

### 6. Orchestration

`backend/services/report_service.py` coordinates data retrieval, case-state
overrides, and optional LLM narrative augmentation.

### 7. Verification loop

`backend/services/verification_service.py` provides:

- `build_verification_delta(old_cases, new_cases)`
- previous-vs-current scan comparison using persisted `report_run` snapshots

Comparison focuses on:

- risk score delta
- reachability verdict shifts
- fix availability shifts
- closure recommendation per case

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

## Current v2 Report Shape

### Stakeholder report

Primary sections:

- `posture_summary`
- `top_priority_actions`
- `impact_summary`
- `current_action_snapshot`
- `next_verification_checkpoint`

### Developer report

Primary sections:

- `triage_summary`
- `decision_tier_counts`
- `technical_findings`
- `dependency_context`
- `reachability_evidence`
- `recommended_fixes`
- `verification_delta`
- `verification_targets`

## Stakeholder PDF Export

Stakeholder view supports PDF export via `backend/services/report_export_service.py`.
The PDF includes posture summary, narrative, top actions, impact summary,
current action snapshot, and verification note.

## UI Mapping

Repository view presents:

- `Security Alerts`
- `Stakeholder Report`
- `Developer Report`

Legacy scenario analysis is preserved under internal/debug expanders only.
`retrieval_scenarios.py` is helper/debug code, not the primary product path.

## LLM Role

LLM is an augmentation layer only:

- reports remain valid if LLM is disabled/unavailable
- LLM writes prose/narrative over an existing deterministic report object
- stakeholder and developer prompts are audience-separated
- LLM must not invent schema fields or act as source of truth
