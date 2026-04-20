"""
frontend/query_language.py - Lightweight query parser/evaluator for Query Workbench.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import re
from typing import Any


TOKEN_PATTERN = re.compile(
    r"""
    "(?:\\.|[^"])*"
    |'(?:\\.|[^'])*'
    |\bAND\b
    |\bOR\b
    |\bNOT\b
    |\bcontains_any\b
    |\bcontains_all\b
    |\bstarts_with\b
    |\bends_with\b
    |\bcontains\b
    |\bexists\b
    |\bin\b
    |>=|<=|!=|=|>|<
    |\(|\)|\[|\]|,
    |\d+\.\d+
    |\d+
    |[A-Za-z_][A-Za-z0-9_]*
    """,
    re.IGNORECASE | re.VERBOSE,
)


COMPARISON_OPERATORS = {
    "=",
    "!=",
    ">",
    ">=",
    "<",
    "<=",
    "contains",
    "starts_with",
    "ends_with",
    "in",
    "exists",
    "contains_any",
    "contains_all",
}


class QuerySyntaxError(ValueError):
    """Raised when the query string cannot be parsed."""


@dataclass
class Comparison:
    field: str
    operator: str
    value: Any = None


@dataclass
class UnaryExpression:
    operator: str
    operand: Any


@dataclass
class BinaryExpression:
    operator: str
    left: Any
    right: Any


def _tokenize(query: str) -> list[str]:
    tokens = [match.group(0) for match in TOKEN_PATTERN.finditer(query)]
    compact = re.sub(r"\s+", "", query)
    rebuilt = re.sub(r"\s+", "", "".join(tokens))
    if compact != rebuilt:
        raise QuerySyntaxError("Query contains unsupported syntax. Use quoted strings for values with punctuation.")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.index = 0

    def parse(self) -> Any:
        if not self.tokens:
            raise QuerySyntaxError("Query is empty.")
        expr = self._parse_or()
        if self._peek() is not None:
            raise QuerySyntaxError(f"Unexpected token: {self._peek()}")
        return expr

    def _parse_or(self) -> Any:
        expr = self._parse_and()
        while self._peek_upper() == "OR":
            self._consume()
            expr = BinaryExpression("OR", expr, self._parse_and())
        return expr

    def _parse_and(self) -> Any:
        expr = self._parse_unary()
        while self._peek_upper() == "AND":
            self._consume()
            expr = BinaryExpression("AND", expr, self._parse_unary())
        return expr

    def _parse_unary(self) -> Any:
        if self._peek_upper() == "NOT":
            self._consume()
            return UnaryExpression("NOT", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        if self._peek() == "(":
            self._consume()
            expr = self._parse_or()
            self._expect(")")
            return expr
        return self._parse_comparison()

    def _parse_comparison(self) -> Comparison:
        field = self._consume_identifier()
        operator = self._consume()
        if operator is None:
            raise QuerySyntaxError(f"Missing operator after field '{field}'.")
        operator_lower = operator.lower()
        if operator_lower not in COMPARISON_OPERATORS:
            raise QuerySyntaxError(f"Unsupported operator '{operator}'.")
        if operator_lower == "exists":
            return Comparison(field, operator_lower)
        value = self._parse_value()
        return Comparison(field, operator_lower, value)

    def _parse_value(self) -> Any:
        token = self._peek()
        if token in ("(", "["):
            return self._parse_list()
        return _parse_scalar(self._consume())

    def _parse_list(self) -> list[Any]:
        opening = self._consume()
        closing = ")" if opening == "(" else "]"
        values: list[Any] = []
        while self._peek() != closing:
            if self._peek() is None:
                raise QuerySyntaxError("Unclosed list value.")
            values.append(self._parse_value())
            if self._peek() == ",":
                self._consume()
            elif self._peek() != closing:
                raise QuerySyntaxError("List values must be separated by commas.")
        self._expect(closing)
        return values

    def _consume_identifier(self) -> str:
        token = self._consume()
        if token is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            raise QuerySyntaxError(f"Expected field name, got '{token}'.")
        return token

    def _expect(self, token: str) -> None:
        if self._consume() != token:
            raise QuerySyntaxError(f"Expected '{token}'.")

    def _peek(self) -> str | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def _peek_upper(self) -> str | None:
        token = self._peek()
        return token.upper() if token is not None else None

    def _consume(self) -> str | None:
        token = self._peek()
        if token is not None:
            self.index += 1
        return token


def _parse_scalar(token: str | None) -> Any:
    if token is None:
        raise QuerySyntaxError("Missing value.")
    if token.startswith(("\"", "'")) and token.endswith(("\"", "'")):
        return token[1:-1]
    token_lower = token.lower()
    if token_lower == "true":
        return True
    if token_lower == "false":
        return False
    if re.fullmatch(r"\d+\.\d+", token):
        return float(token)
    if re.fullmatch(r"\d+", token):
        return int(token)
    return token


def parse_query(query: str) -> Any:
    return _Parser(_tokenize(query)).parse()


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return value
    if isinstance(value, str):
        return value.strip()
    return value


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _to_lower(value: Any) -> str:
    return str(value).strip().lower()


def _coerce_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(raw[:10])
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _compare_ordered(left: Any, right: Any, operator: str) -> bool:
    left_dt = _coerce_datetime(left)
    right_dt = _coerce_datetime(right)
    if left_dt and right_dt:
        left_cmp, right_cmp = left_dt, right_dt
    else:
        left_cmp, right_cmp = left, right
    if left_cmp is None or right_cmp is None:
        return False
    try:
        if operator == ">":
            return left_cmp > right_cmp
        if operator == ">=":
            return left_cmp >= right_cmp
        if operator == "<":
            return left_cmp < right_cmp
        if operator == "<=":
            return left_cmp <= right_cmp
    except TypeError:
        return False
    return False


def _field_exists(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def evaluate_expression(expr: Any, row: dict[str, Any]) -> bool:
    if isinstance(expr, BinaryExpression):
        if expr.operator == "AND":
            return evaluate_expression(expr.left, row) and evaluate_expression(expr.right, row)
        return evaluate_expression(expr.left, row) or evaluate_expression(expr.right, row)
    if isinstance(expr, UnaryExpression):
        return not evaluate_expression(expr.operand, row)
    if isinstance(expr, Comparison):
        return _evaluate_comparison(expr, row)
    raise QuerySyntaxError("Unsupported expression tree.")


def _evaluate_comparison(expr: Comparison, row: dict[str, Any]) -> bool:
    left = row.get(expr.field)
    op = expr.operator
    right = expr.value

    if op == "exists":
        return _field_exists(left)

    if op in {">", ">=", "<", "<="}:
        return _compare_ordered(left, right, op)

    if op == "=":
        return _normalize_scalar(left) == _normalize_scalar(right)
    if op == "!=":
        return _normalize_scalar(left) != _normalize_scalar(right)

    if op == "contains":
        if isinstance(left, (list, tuple, set)):
            return any(_to_lower(item) == _to_lower(right) for item in left)
        if left is None:
            return False
        return _to_lower(right) in _to_lower(left)

    if op == "starts_with":
        return left is not None and _to_lower(left).startswith(_to_lower(right))

    if op == "ends_with":
        return left is not None and _to_lower(left).endswith(_to_lower(right))

    if op == "in":
        if not isinstance(right, list):
            raise QuerySyntaxError("Operator 'in' requires a list value.")
        normalized = {_to_lower(item) if isinstance(item, str) else item for item in right}
        left_normalized = _to_lower(left) if isinstance(left, str) else left
        return left_normalized in normalized

    if op == "contains_any":
        if not isinstance(right, list):
            raise QuerySyntaxError("Operator 'contains_any' requires a list value.")
        values = [_to_lower(item) for item in _as_list(left)]
        needles = {_to_lower(item) for item in right}
        return any(value in needles for value in values)

    if op == "contains_all":
        if not isinstance(right, list):
            raise QuerySyntaxError("Operator 'contains_all' requires a list value.")
        values = {_to_lower(item) for item in _as_list(left)}
        needles = {_to_lower(item) for item in right}
        return needles.issubset(values)

    raise QuerySyntaxError(f"Operator '{op}' is not implemented.")
