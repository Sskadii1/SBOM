from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from frontend.query_builder import build_query_from_rules
from frontend.query_language import evaluate_expression, parse_query


SAMPLE_ROWS = [
    {
        "project": "alpha/repo",
        "severity": "critical",
        "cvss": 9.8,
        "epss": 0.91,
        "kev": True,
        "risk_score": 92.4,
        "reachability_verdict": "confirmed_reachable",
        "fix_available": True,
        "fix_versions_count": 2,
        "all_scopes": ["required", "runtime"],
        "closest_depth": 1,
        "cwe": ["CWE-79", "CWE-94"],
        "published": "2026-01-10",
        "call_locations_count": 3,
    },
    {
        "project": "beta/repo",
        "severity": "high",
        "cvss": 7.4,
        "epss": 0.15,
        "kev": False,
        "risk_score": 61.2,
        "reachability_verdict": "likely_reachable",
        "fix_available": False,
        "fix_versions_count": 0,
        "all_scopes": ["optional"],
        "closest_depth": 3,
        "cwe": ["CWE-22"],
        "published": "2024-05-01",
        "call_locations_count": 0,
    },
    {
        "project": "gamma/repo",
        "severity": "medium",
        "cvss": 5.6,
        "epss": 0.02,
        "kev": False,
        "risk_score": 34.7,
        "reachability_verdict": "no_sink_data",
        "fix_available": True,
        "fix_versions_count": 1,
        "all_scopes": ["dev"],
        "closest_depth": 5,
        "cwe": [],
        "published": "2023-08-15",
        "call_locations_count": 0,
    },
]


class QueryBuilderTests(unittest.TestCase):
    def test_builds_combined_query(self) -> None:
        query = build_query_from_rules(
            [
                {"field": "severity", "operator": "in", "value": ["critical", "high"], "negated": False},
                {"field": "fix_available", "operator": "=", "value": True, "negated": False},
                {"field": "project", "operator": "=", "value": "alpha/repo", "negated": True},
            ],
            conjunction="AND",
        )
        self.assertEqual(
            query,
            'severity in ("critical", "high") AND fix_available = true AND NOT (project = "alpha/repo")',
        )


class QueryLanguageTests(unittest.TestCase):
    def _match_projects(self, query: str) -> list[str]:
        expr = parse_query(query)
        return [row["project"] for row in SAMPLE_ROWS if evaluate_expression(expr, row)]

    def test_comparison_and_boolean_filters(self) -> None:
        self.assertEqual(
            self._match_projects('severity in ("critical", "high") AND fix_available = true'),
            ["alpha/repo"],
        )

    def test_or_and_not_logic(self) -> None:
        self.assertEqual(
            self._match_projects('NOT (project = "alpha/repo") AND (kev = true OR risk_score >= 60)'),
            ["beta/repo"],
        )

    def test_array_operators(self) -> None:
        self.assertEqual(
            self._match_projects('all_scopes contains_any ("required", "runtime") OR cwe contains "CWE-22"'),
            ["alpha/repo", "beta/repo"],
        )

    def test_date_comparison(self) -> None:
        self.assertEqual(
            self._match_projects('published >= "2024-01-01"'),
            ["alpha/repo", "beta/repo"],
        )

    def test_presence_operator(self) -> None:
        self.assertEqual(
            self._match_projects("cwe exists AND call_locations_count >= 1"),
            ["alpha/repo"],
        )


if __name__ == "__main__":
    unittest.main()
