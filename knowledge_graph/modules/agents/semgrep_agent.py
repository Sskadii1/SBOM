"""
modules/agents/semgrep_agent.py - Phase 2: Semgrep-based reachability scanner.

modules/agents/semgrep_agent.py - Phase 2: Semgrep-based reachability scanner.

Flow:
  1. Load sinks from cve_sinks.db for the project's vuln_ids
  2. Auto-generate Semgrep rules (YAML) per sink
  3. Run semgrep on repo source code
  4. Parse findings → ReachabilityResult list
  5. Save to data/reachability/{project}.json + cve_sinks.db
"""
import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from modules.agents.sink_db import get_sinks_for_vulns, save_reachability

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_REACH_DIR = _DATA_DIR / "reachability"
_RULES_DIR = _DATA_DIR / "rules"


class _ReadableYamlDumper(yaml.SafeDumper):
    """Prefer block style for multiline strings so generated rules stay readable."""


def _represent_multiline_str(dumper: yaml.SafeDumper, value: str) -> yaml.nodes.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_ReadableYamlDumper.add_representer(str, _represent_multiline_str)

# Verdict score mapping
VERDICT_SCORES: Dict[str, float] = {
    "confirmed_reachable": 1.0,
    "likely_reachable":    0.7,
    "likely_unreachable":  0.3,
    "no_sink_data":        0.5,
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ReachabilityResult:
    vuln_id: str
    package_name: str
    sink_function: Optional[str]
    verdict: str = "no_sink_data"
    reach_score: float = 0.5
    call_locations: List[str] = field(default_factory=list)
    semgrep_rule_id: Optional[str] = None
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Semgrep rule generator
# ---------------------------------------------------------------------------

_GENERIC_FUNCTION_NAMES = {
    # Common generic verbs already present
    "$",
    "apply",
    "call",
    "create",
    "fetch",
    "get",
    "load",
    "match",
    "new",
    "notify",
    "open",
    "parse",
    "post",
    "put",
    "read",
    "request",
    "run",
    "send",
    "set",
    "trim",
    "write",
    # Native JS method names that cause FPs (confirmed in audit)
    "test",       # RegExp.prototype.test() — falsely matched minimatch:test
    "replace",    # String.prototype.replace() — falsely matched helpers:replace
    "push",       # Array.prototype.push() — falsely matched simple-git:push
    "pull",       # common git/array term — falsely matched simple-git:pull
    "clone",      # Object/Array clone — falsely matched simple-git:clone
    "from",       # Buffer.from(), Array.from() — falsely matched axios:from
    "expand",     # internal helpers (dotenv-expand) — falsely matched brace-expansion:expand
    "tostring",   # Number/Object.toString() — falsely matched bn.js:toString
    "valueof",    # Object.valueOf()
    # Other broad verbs that overmatch
    "add",
    "build",
    "check",
    "close",
    "compile",
    "connect",
    "decode",
    "delete",
    "encode",
    "execute",
    "format",
    "handle",
    "init",
    "process",
    "remove",
    "render",
    "start",
    "stop",
    "update",
    "validate",
}

# Native JS constructors / global objects that must NEVER generate raw patterns.
# Patterns like `new RegExp(...)` match native JS regardless of package context.
_NATIVE_JS_CONSTRUCTORS = {
    "RegExp", "URL", "URLSearchParams", "Error", "TypeError", "RangeError",
    "SyntaxError", "ReferenceError", "EvalError", "URIError",
    "Map", "Set", "WeakMap", "WeakSet",
    "Promise", "Date", "Buffer",
    "Array", "Object", "Function", "Symbol", "BigInt",
    "Proxy", "Reflect", "Intl",
}


def _base_package_name(pkg: str, ecosystem: str) -> str:
    """Normalize package names for rule generation without dropping npm scopes."""
    pkg = pkg.split(":")[0]
    if ecosystem == "npm" and pkg.startswith("@"):
        parts = pkg.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else pkg
    if ecosystem == "pypi":
        return pkg.replace("-", "_")
    return pkg


def _quoted_variants(text: str) -> List[str]:
    return [f"'{text}'", f'"{text}"']


def _pattern_either(key: str, values: List[str]) -> Dict[str, Any]:
    unique = list(dict.fromkeys(v for v in values if v))
    return {"pattern-either": [{key: value} for value in unique]}


def _is_generic_function_name(fn: Optional[str]) -> bool:
    if not fn:
        return False
    fn_stripped = fn.strip()
    fn_norm = fn_stripped.lower()
    return (
        fn_norm in _GENERIC_FUNCTION_NAMES
        or fn_stripped in _NATIVE_JS_CONSTRUCTORS
        or len(fn_norm) <= 3
    )


def _extract_fn_from_call_pattern(call_pattern: str) -> Optional[str]:
    """
    Extract a function/method name from a call pattern string.
    E.g. "fetch(...)" → "fetch", "$OBJ.request(...)" → "request",
         "new RegExp(...)" → "RegExp".
    Returns None when no extractable name is found.
    """
    if not call_pattern:
        return None
    s = call_pattern.strip()
    # Constructor: "new ClassName(...)"
    m = re.match(r'^new\s+(\w+)\s*\(', s)
    if m:
        return m.group(1)
    # Method call: "$OBJ.method(...)" or "pkg.method(...)"
    m = re.match(r'^(?:\$\w+|\w[\w.-]*)\.(\w+)\s*\(', s)
    if m:
        return m.group(1)
    # Bare call: "funcName(...)"
    m = re.match(r'^(\w+)\s*\(', s)
    if m and not m.group(1).startswith("$"):
        return m.group(1)
    return None


def _is_wildcard_pattern(call_pattern: Optional[str]) -> bool:
    """Return True when the call pattern uses a $ANY-style wildcard method."""
    return bool(call_pattern and "$ANY" in call_pattern)


def _is_endpoint_pattern(call_pattern: Optional[str]) -> bool:
    """Return True when the call pattern describes an HTTP route rather than a function."""
    if not call_pattern:
        return False
    s = call_pattern.strip()
    return (
        s.startswith("/")
        or bool(re.search(r'\bendpoint\b', s, re.IGNORECASE))
        or bool(re.search(r'@routes?\.\w+\(', s))
        or bool(re.match(r'^(GET|POST|PUT|DELETE|PATCH)\s+/', s))
    )


def _should_keep_raw_call_pattern(
    original_call_pattern: Optional[str],
    normalized_call_pattern: Optional[str],
    direct_name: Optional[str],
) -> bool:
    """
    Keep raw call patterns only when they are specific enough.

    Generic method names such as `.request(...)` or `.get(...)` become
    `$OBJ.request(...)` / `$OBJ.get(...)`, which overmatch unrelated objects.
    Native JS constructors (RegExp, URL, Error …) must never produce raw patterns.
    Those should rely on import-aware patterns instead.

    BUG FIX: When direct_name is None (fn was not extracted from the DB),
    we must still inspect the call_pattern itself to decide whether the implied
    function name is generic — otherwise naked patterns like `fetch(...)` or
    `new RegExp(...)` get emitted without any package-provenance guard.
    """
    if not normalized_call_pattern:
        return False

    # Resolve the effective function name.
    # Prefer the explicitly provided direct_name; fall back to extracting
    # it from the call pattern string when direct_name is absent.
    effective_name = direct_name
    if not effective_name:
        effective_name = _extract_fn_from_call_pattern(normalized_call_pattern)

    # Hard-block native JS constructors regardless of call pattern specificity.
    if effective_name and effective_name in _NATIVE_JS_CONSTRUCTORS:
        return False

    if effective_name and _is_generic_function_name(effective_name):
        original = (original_call_pattern or "").strip()
        normalized = normalized_call_pattern.strip()
        too_broad = {
            f"{effective_name}(...)",
            f".{effective_name}(...)",
            f"$OBJ.{effective_name}(...)",
            f"new {effective_name}(...)",
            f"new $OBJ.{effective_name}(...)",
        }
        return original not in too_broad and normalized not in too_broad

    # Cannot determine a name at all — be conservative and suppress.
    if not effective_name:
        return False

    return True


def _js_module_contexts(pkg: str) -> List[str]:
    contexts: List[str] = []
    for quoted in _quoted_variants(pkg):
        contexts.extend([
            f"const $MOD = require({quoted});\n...",
            f"let $MOD = require({quoted});\n...",
            f"var $MOD = require({quoted});\n...",
            f"import $MOD from {quoted};\n...",
            f"import * as $MOD from {quoted};\n...",
            f"$MOD = await import({quoted})\n...",
            f"$MOD = (await import({quoted})).default\n...",
        ])
    return contexts


def _js_named_import_contexts(pkg: str, fn: str) -> List[str]:
    contexts: List[str] = []
    for quoted in _quoted_variants(pkg):
        contexts.extend([
            f"const {{ {fn} }} = require({quoted});\n...",
            f"import {{ {fn} }} from {quoted};\n...",
        ])
    return contexts


def _js_named_alias_contexts(pkg: str, fn: str) -> List[str]:
    contexts: List[str] = []
    for quoted in _quoted_variants(pkg):
        contexts.extend([
            f"const {{ {fn}: $FN }} = require({quoted});\n...",
            f"import {{ {fn} as $FN }} from {quoted};\n...",
        ])
    return contexts


def _py_module_contexts(pkg: str) -> List[str]:
    return [
        f"import {pkg}\n...",
        f"import {pkg} as $MOD\n...",
    ]


def _py_named_import_contexts(pkg: str, fn: str) -> List[str]:
    return [f"from {pkg} import {fn}\n..."]


def _py_named_alias_contexts(pkg: str, fn: str) -> List[str]:
    return [f"from {pkg} import {fn} as $FN\n..."]


def _js_direct_context_patterns(pkg: str, fn: Optional[str], sink_type: str) -> List[Dict[str, Any]]:
    if sink_type == "constructor":
        ctor = fn
        if not ctor:
            return []
        return [
            {
                "patterns": [
                    _pattern_either("pattern", [f"new $MOD.{ctor}(...)"]),
                    _pattern_either("pattern-inside", _js_module_contexts(pkg)),
                ]
            },
            {
                "patterns": [
                    {"pattern": f"new {ctor}(...)"},
                    _pattern_either("pattern-inside", _js_named_import_contexts(pkg, ctor)),
                ]
            },
            {
                "patterns": [
                    {"pattern": "new $FN(...)"},
                    _pattern_either("pattern-inside", _js_named_alias_contexts(pkg, ctor)),
                ]
            },
        ]

    if fn:
        return [
            {
                "patterns": [
                    _pattern_either(
                        "pattern",
                        [f"$MOD.{fn}(...)"] + [f"require({quoted}).{fn}(...)" for quoted in _quoted_variants(pkg)],
                    ),
                    _pattern_either("pattern-inside", _js_module_contexts(pkg)),
                ]
            },
            {
                "patterns": [
                    {"pattern": f"{fn}(...)"},
                    _pattern_either("pattern-inside", _js_named_import_contexts(pkg, fn)),
                ]
            },
            {
                "patterns": [
                    {"pattern": "$FN(...)"},
                    _pattern_either("pattern-inside", _js_named_alias_contexts(pkg, fn)),
                ]
            },
        ]

    return [
        {
            "patterns": [
                _pattern_either(
                    "pattern",
                    ["$MOD(...)"] + [f"require({quoted})(...)" for quoted in _quoted_variants(pkg)],
                ),
                _pattern_either("pattern-inside", _js_module_contexts(pkg)),
            ]
        }
    ]


def _py_direct_context_patterns(pkg: str, fn: Optional[str], sink_type: str) -> List[Dict[str, Any]]:
    if sink_type == "constructor":
        ctor = fn
        if not ctor:
            return []
        return [
            {
                "patterns": [
                    _pattern_either("pattern", [f"{pkg}.{ctor}(...)"]),
                    _pattern_either("pattern-inside", _py_module_contexts(pkg)),
                ]
            },
            {
                "patterns": [
                    {"pattern": f"{ctor}(...)"},
                    _pattern_either("pattern-inside", _py_named_import_contexts(pkg, ctor)),
                ]
            },
            {
                "patterns": [
                    {"pattern": "$FN(...)"},
                    _pattern_either("pattern-inside", _py_named_alias_contexts(pkg, ctor)),
                ]
            },
        ]

    if fn:
        return [
            {
                "patterns": [
                    _pattern_either("pattern", [f"{pkg}.{fn}(...)", f"$MOD.{fn}(...)"]),
                    _pattern_either("pattern-inside", _py_module_contexts(pkg)),
                ]
            },
            {
                "patterns": [
                    {"pattern": f"{fn}(...)"},
                    _pattern_either("pattern-inside", _py_named_import_contexts(pkg, fn)),
                ]
            },
            {
                "patterns": [
                    {"pattern": "$FN(...)"},
                    _pattern_either("pattern-inside", _py_named_alias_contexts(pkg, fn)),
                ]
            },
        ]

    return [
        {
            "patterns": [
                _pattern_either("pattern", [f"{pkg}(...)", "$MOD(...)"]),
                _pattern_either("pattern-inside", _py_module_contexts(pkg)),
            ]
        }
    ]


def _contextual_direct_patterns(
    ecosystem: str,
    pkg: str,
    fn: Optional[str],
    sink_type: str,
) -> List[Dict[str, Any]]:
    if ecosystem == "npm":
        return _js_direct_context_patterns(pkg, fn, sink_type)
    if ecosystem == "pypi":
        return _py_direct_context_patterns(pkg, fn, sink_type)
    return []


_PYTHON_PACKAGE_IMPORT_ROOTS: Dict[str, List[str]] = {
    "authlib": ["authlib", "authlib.jose"],
    "fastmcp": ["fastmcp"],
    "gradio": ["gradio"],
    "langchain-core": ["langchain_core"],
    "marshmallow": ["marshmallow"],
    "mcp": ["mcp", "mcp.server.fastmcp", "fastmcp"],
    "pdfminer-six": ["pdfminer"],
    "pillow": ["PIL", "PIL.Image"],
    "pyjwt": ["jwt"],
    "urllib3": ["urllib3"],
    "wheel": ["wheel"],
}

_PYTHON_MEMBER_OWNER_HINTS: Dict[tuple[str, str], List[tuple[str, str]]] = {
    ("authlib", "decode"): [("authlib.jose", "jwt")],
    ("marshmallow", "load"): [("marshmallow", "Schema")],
    ("pillow", "open"): [("PIL", "Image")],
    ("urllib3", "read"): [("urllib3.response", "HTTPResponse")],
}

_PYTHON_ALWAYS_STRICT_NAMES = {
    "decode",
    "get",
    "load",
    "loads",
    "open",
    "read",
    "unpack",
}


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    return list(dict.fromkeys(v for v in values if v))


def _dedupe_rule_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    unique: List[Dict[str, Any]] = []
    for entry in entries:
        marker = json.dumps(entry, sort_keys=True)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(entry)
    return unique


def _normalized_python_package_key(pkg: str) -> str:
    return (pkg or "").strip().lower()


def _extract_python_call_target(call_pattern: Optional[str]) -> Dict[str, Optional[str]]:
    if not call_pattern:
        return {"kind": None, "qualifier": None, "member": None}

    text = call_pattern.strip()
    if text.startswith("new "):
        text = text[4:].strip()

    var_match = re.match(r"^(\$[A-Za-z_][\w]*)\.([A-Za-z_][\w]*)\s*\(", text)
    if var_match:
        return {
            "kind": "variable",
            "qualifier": var_match.group(1),
            "member": var_match.group(2),
        }

    qualified_match = re.match(r"^([A-Za-z_][\w.]*)\.([A-Za-z_][\w]*)\s*\(", text)
    if qualified_match:
        return {
            "kind": "qualified",
            "qualifier": qualified_match.group(1),
            "member": qualified_match.group(2),
        }

    bare_match = re.match(r"^([A-Za-z_][\w]*)\s*\(", text)
    if bare_match:
        return {
            "kind": "bare",
            "qualifier": None,
            "member": bare_match.group(1),
        }

    return {"kind": None, "qualifier": None, "member": None}


def _python_symbol_name(
    fn: Optional[str],
    cls: Optional[str],
    sink_type: str,
    call_target: Dict[str, Optional[str]],
) -> Optional[str]:
    if sink_type == "constructor" and cls:
        return cls
    if fn:
        return fn
    return call_target.get("member")


def _is_python_ambiguous_symbol(name: Optional[str]) -> bool:
    if not name:
        return False
    lowered = name.strip().lower()
    return lowered in _PYTHON_ALWAYS_STRICT_NAMES or _is_generic_function_name(name)


def _python_distribution_import_roots(pkg: str) -> List[str]:
    roots = list(_PYTHON_PACKAGE_IMPORT_ROOTS.get(_normalized_python_package_key(pkg), []))
    if not roots:
        base_root = _base_package_name(pkg, "pypi")
        if base_root:
            roots.append(base_root)
    return _dedupe_preserve_order(roots)


def _is_related_python_root(candidate: str, roots: List[str]) -> bool:
    return any(
        candidate == root
        or candidate.startswith(root + ".")
        or root.startswith(candidate + ".")
        for root in roots
    )


def _python_import_roots(
    pkg: str,
    call_target: Dict[str, Optional[str]],
) -> List[str]:
    roots = _python_distribution_import_roots(pkg)
    qualifier = (call_target.get("qualifier") or "").strip()
    if qualifier and qualifier[:1].islower() and _is_related_python_root(qualifier, roots):
        roots.append(qualifier)
    return _dedupe_preserve_order(roots)


def _py_import_patterns_for_roots(import_roots: List[str]) -> List[Dict[str, Any]]:
    patterns: List[Dict[str, Any]] = []
    for root in import_roots:
        root_re = re.escape(root)
        patterns.extend([
            {"pattern-regex": rf"(?m)^\s*import\s+{root_re}\b(?:\s+as\s+[A-Za-z_]\w*)?"},
            {"pattern-regex": rf"(?m)^\s*from\s+{root_re}(?:\.[A-Za-z_]\w*)*\s+import\b"},
        ])
    return _dedupe_rule_entries(patterns)


def _py_exact_named_symbol_patterns(import_root: str, symbol: str) -> List[Dict[str, Any]]:
    return [
        {
            "patterns": [
                {"pattern": f"{symbol}(...)"},
                {"pattern-inside": f"from {import_root} import {symbol}\n..."},
            ]
        }
    ]


def _py_relaxed_named_symbol_pattern(symbol: str) -> Dict[str, Any]:
    return {"pattern": f"{symbol}(...)"}


def _py_import_module_regex(import_root: str) -> str:
    root_re = re.escape(import_root)
    return rf"(?m)^\s*import\s+{root_re}\b(?:\s+as\s+[A-Za-z_]\w*)?"


def _py_from_import_symbol_regex(import_root: str, symbol: str) -> str:
    root_re = re.escape(import_root)
    symbol_re = re.escape(symbol)
    return rf"(?ms)^\s*from\s+{root_re}(?:\.[A-Za-z_]\w*)*\s+import\s*(?:\(|\\)?[\s\S]*?\b{symbol_re}\b"


def _py_regex_named_symbol_patterns(import_root: str, symbol: str) -> List[Dict[str, Any]]:
    return [
        {
            "patterns": [
                {"pattern": f"{symbol}(...)"},
                {"pattern-regex": _py_from_import_symbol_regex(import_root, symbol)},
            ]
        }
    ]


def _py_exact_module_member_patterns(import_root: str, member: str) -> List[Dict[str, Any]]:
    module_name = import_root.split(".")[-1]
    candidates = _dedupe_preserve_order([import_root, module_name])
    return [
        {
            "patterns": [
                {"pattern": f"{candidate}.{member}(...)"},
                {"pattern-inside": f"import {import_root}\n..."},
            ]
        }
        for candidate in candidates
    ]


def _py_regex_module_member_patterns(import_root: str, member: str) -> List[Dict[str, Any]]:
    module_name = import_root.split(".")[-1]
    candidates = _dedupe_preserve_order([import_root, module_name])
    return [
        {
            "patterns": [
                {"pattern": f"{candidate}.{member}(...)"},
                {"pattern-regex": _py_import_module_regex(import_root)},
            ]
        }
        for candidate in candidates
    ]


def _py_exact_qualified_symbol_patterns(import_root: str, qualifier: str, member: str) -> List[Dict[str, Any]]:
    if not qualifier or "." in qualifier:
        return []
    return [
        {
            "patterns": [
                {"pattern": f"{qualifier}.{member}(...)"},
                {"pattern-inside": f"from {import_root} import {qualifier}\n..."},
            ]
        }
    ]


def _py_regex_qualified_symbol_patterns(import_root: str, qualifier: str, member: str) -> List[Dict[str, Any]]:
    if not qualifier or "." in qualifier:
        return []
    return [
        {
            "patterns": [
                {"pattern": f"{qualifier}.{member}(...)"},
                {"pattern-regex": _py_from_import_symbol_regex(import_root, qualifier)},
            ]
        }
    ]


def _py_relaxed_qualified_symbol_pattern(qualifier: str, member: str) -> Optional[Dict[str, Any]]:
    if not qualifier or "." in qualifier:
        return None
    if not qualifier[:1].isupper():
        return None
    return {"pattern": f"{qualifier}.{member}(...)"}


def _python_owner_hints(
    pkg: str,
    symbol_name: Optional[str],
    call_target: Dict[str, Optional[str]],
    import_roots: List[str],
) -> List[tuple[str, str]]:
    qualifier = (call_target.get("qualifier") or "").strip()
    if (
        qualifier
        and not qualifier.startswith("$")
        and "." not in qualifier
        and qualifier[:1].isupper()
    ):
        return [(root, qualifier) for root in import_roots]

    if not symbol_name:
        return []
    return list(
        _PYTHON_MEMBER_OWNER_HINTS.get(
            (_normalized_python_package_key(pkg), symbol_name),
            [],
        )
    )


def _make_python_rules(sink: Dict[str, Any]) -> List[Dict[str, Any]]:
    vuln_id = sink["vuln_id"]
    pkg = sink["package_name"]
    fn = sink.get("function_name") or ""
    cls = sink.get("class_name")
    call_pattern = sink.get("call_pattern")
    sink_type = sink.get("sink_type", "function_call")

    call_target = _extract_python_call_target(call_pattern)
    symbol_name = _python_symbol_name(fn or None, cls, sink_type, call_target)
    import_roots = _python_import_roots(pkg, call_target)
    is_weak_sink = _is_wildcard_pattern(call_pattern) or _is_endpoint_pattern(call_pattern)
    is_ambiguous_symbol = _is_python_ambiguous_symbol(symbol_name)

    if is_weak_sink:
        sink_quality = "weak"
    elif symbol_name and not is_ambiguous_symbol:
        sink_quality = "strong"
    else:
        sink_quality = "generic"

    qualifier = (call_target.get("qualifier") or "").strip()
    member_name = call_target.get("member") or symbol_name
    owner_hints = _python_owner_hints(pkg, symbol_name, call_target, import_roots)

    fn_slug = ((symbol_name or fn) or "any").replace(".", "_").replace("$", "")
    base_id = f"sbom-reach-{vuln_id.lower().replace('-','_').replace('/','_')}-{fn_slug}"
    languages = ["python"]
    generated_rules: List[Dict[str, Any]] = []

    direct_rule_entries: List[Dict[str, Any]] = []
    if not is_weak_sink and symbol_name:
        if qualifier and not qualifier.startswith("$") and member_name:
            for import_root in import_roots:
                if _is_related_python_root(qualifier, [import_root]):
                    direct_rule_entries.extend(
                        _py_exact_module_member_patterns(import_root, member_name)
                    )
                    direct_rule_entries.extend(
                        _py_regex_module_member_patterns(import_root, member_name)
                    )
            for import_root, owner in owner_hints:
                direct_rule_entries.extend(
                    _py_exact_qualified_symbol_patterns(import_root, owner, member_name)
                )
                direct_rule_entries.extend(
                    _py_regex_qualified_symbol_patterns(import_root, owner, member_name)
                )
            relaxed_owner_pattern = _py_relaxed_qualified_symbol_pattern(qualifier, member_name)
            if relaxed_owner_pattern:
                direct_rule_entries.append(relaxed_owner_pattern)
        elif sink_type == "constructor":
            for import_root in import_roots:
                direct_rule_entries.extend(
                    _py_exact_named_symbol_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_named_symbol_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_exact_module_member_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_module_member_patterns(import_root, symbol_name)
                )
            if not is_ambiguous_symbol:
                direct_rule_entries.append(_py_relaxed_named_symbol_pattern(symbol_name))
        elif is_ambiguous_symbol:
            for import_root in import_roots:
                direct_rule_entries.extend(
                    _py_exact_named_symbol_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_named_symbol_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_exact_module_member_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_module_member_patterns(import_root, symbol_name)
                )
            for import_root, owner in owner_hints:
                direct_rule_entries.extend(
                    _py_exact_qualified_symbol_patterns(import_root, owner, member_name or symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_qualified_symbol_patterns(import_root, owner, member_name or symbol_name)
                )
                relaxed_owner_pattern = _py_relaxed_qualified_symbol_pattern(owner, member_name or symbol_name)
                if relaxed_owner_pattern:
                    direct_rule_entries.append(relaxed_owner_pattern)
        else:
            for import_root in import_roots:
                direct_rule_entries.extend(
                    _py_exact_named_symbol_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_named_symbol_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_exact_module_member_patterns(import_root, symbol_name)
                )
                direct_rule_entries.extend(
                    _py_regex_module_member_patterns(import_root, symbol_name)
                )
            if not is_ambiguous_symbol:
                direct_rule_entries.append(_py_relaxed_named_symbol_pattern(symbol_name))

    direct_rule_entries = _dedupe_rule_entries(direct_rule_entries)
    if direct_rule_entries:
        rule_direct: Dict[str, Any] = {
            "id": f"{base_id}-direct",
            "message": f"{vuln_id}: vulnerable sink '{symbol_name or pkg}' directly called - package {pkg}",
            "severity": "WARNING",
            "languages": languages,
            "metadata": {
                "vuln_id": vuln_id,
                "package": pkg,
                "tier": "direct",
                "sink_quality": sink_quality,
                "confidence": str(sink.get("confidence", 1.0)),
                **({"sink_function": symbol_name} if symbol_name else {}),
            },
        }
        if len(direct_rule_entries) == 1 and "pattern" in direct_rule_entries[0]:
            rule_direct["pattern"] = direct_rule_entries[0]["pattern"]
        else:
            rule_direct["pattern-either"] = direct_rule_entries
        generated_rules.append(rule_direct)

    import_patterns = _py_import_patterns_for_roots(import_roots)
    if import_patterns:
        generated_rules.append(
            {
                "id": f"{base_id}-import",
                "message": f"{vuln_id}: vulnerable package '{pkg}' imported but code paths may vary",
                "severity": "INFO",
                "languages": languages,
                "metadata": {
                    "vuln_id": vuln_id,
                    "package": pkg,
                    "tier": "import",
                    "sink_quality": sink_quality,
                },
                "pattern-either": import_patterns,
            }
        )

    return generated_rules


def _make_rules(sink: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build a list of Semgrep rules reflecting different reachability tiers.
    Returns:
       - Direct usage rule (tier: direct)   — omitted for wildcard / endpoint sinks
       - Package import rule (tier: import)

    Sink quality levels (stored in rule metadata):
      "strong"  — specific, non-generic function name with import provenance
      "generic" — generic function name; direct-tier only via import-aware patterns
      "weak"    — wildcard ($ANY) or endpoint pattern; direct-tier suppressed entirely
    """
    ecosystem = sink.get("ecosystem", "")
    if ecosystem == "pypi":
        return _make_python_rules(sink)

    vuln_id = sink["vuln_id"]
    pkg = sink["package_name"]
    fn = sink.get("function_name") or ""   # normalise None → ""
    cls = sink.get("class_name")
    call_pattern = sink.get("call_pattern")
    original_call_pattern = call_pattern
    sink_type = sink.get("sink_type", "function_call")

    # --- Normalize fn from call_pattern when DB field is empty ---------------
    # This gives import-aware patterns a concrete function name to bind to
    # (e.g. call_pattern="fetch(...)" → fn="fetch") and fixes the case where
    # direct_name=None caused _should_keep_raw_call_pattern to return True
    # unconditionally, leaking naked patterns like `fetch(...)` into rules.
    if not fn and call_pattern:
        extracted = _extract_fn_from_call_pattern(call_pattern)
        if extracted and not extracted.startswith("$"):
            fn = extracted

    direct_name = cls if sink_type == "constructor" and cls else (fn or None)

    # --- Detect weak / endpoint sinks ----------------------------------------
    # Wildcard ($ANY) and HTTP-endpoint patterns cannot be expressed as
    # meaningful direct-call Semgrep rules; emit only the import-tier rule so
    # reachability falls back to "likely_reachable" / "likely_unreachable".
    is_weak_sink = _is_wildcard_pattern(original_call_pattern) or _is_endpoint_pattern(original_call_pattern)

    # --- Determine sink quality for verdict capping in parse_findings() ------
    if is_weak_sink:
        sink_quality = "weak"
    elif direct_name and not _is_generic_function_name(direct_name):
        sink_quality = "strong"
    else:
        sink_quality = "generic"

    fn_slug = (fn or "any").replace(".", "_").replace("$", "")
    base_id = f"sbom-reach-{vuln_id.lower().replace('-','_').replace('/','_')}-{fn_slug}"
    base_pkg = _base_package_name(pkg, ecosystem)

    lang_map = {
        "npm": ["javascript", "typescript"],
        "pypi": ["python"],
        "cargo": ["rust"],
        "maven": ["java"],
    }
    languages = lang_map.get(ecosystem, ["javascript", "python"])

    generated_rules = []

    # 1. Direct Call Rule (-direct)
    # Skipped entirely for weak (wildcard / endpoint) sinks — those rely on
    # the import-tier rule only, and matches there yield "likely_reachable".
    if not is_weak_sink:
        direct_rule_entries: List[Dict[str, Any]] = []
        direct_patterns = []
        if call_pattern:
            if call_pattern.startswith("."):
                call_pattern = f"$OBJ{call_pattern}"
            if " or " in call_pattern:
                parts = [p.strip() for p in call_pattern.split(" or ")]
                valid = [p for p in parts if "(...)" in p or "..." in p]
                if valid:
                    call_pattern = valid[0]
            if "(...)" in call_pattern or "..." in call_pattern:
                direct_patterns.append({"pattern": call_pattern})
        elif sink_type == "constructor" and direct_name:
            direct_patterns.extend([
                {"pattern": f"new {direct_name}(...)"},
                {"pattern": f"new $OBJ.{direct_name}(...)"},
            ])
        elif fn and cls:
            direct_patterns.append({"pattern": f"$OBJ.{fn}(...)"})
        elif direct_name:
            direct_patterns.extend([
                {"pattern": f"{direct_name}(...)"},
                {"pattern": f"$OBJ.{direct_name}(...)"},
            ])

        direct_rule_entries.extend(
            _contextual_direct_patterns(
                ecosystem,
                base_pkg,
                direct_name,
                sink_type,
            )
        )
        keep_raw_patterns = False
        if call_pattern:
            keep_raw_patterns = any(
                _should_keep_raw_call_pattern(original_call_pattern, entry.get("pattern"), direct_name)
                for entry in direct_patterns
            )
        elif direct_name and not _is_generic_function_name(direct_name):
            keep_raw_patterns = True

        if direct_patterns and keep_raw_patterns:
            if len(direct_patterns) == 1:
                direct_rule_entries.append(direct_patterns[0])
            else:
                direct_rule_entries.append({"pattern-either": direct_patterns})

        if direct_rule_entries:
            rule_direct: Dict[str, Any] = {
                "id": f"{base_id}-direct",
                "message": f"{vuln_id}: vulnerable sink '{fn or pkg}' directly called - package {pkg}",
                "severity": "WARNING",
                "languages": languages,
                "metadata": {
                    "vuln_id": vuln_id,
                    "package": pkg,
                    "tier": "direct",
                    "sink_quality": sink_quality,
                    "confidence": str(sink.get("confidence", 1.0)),
                    **({"sink_function": fn} if fn else {}),
                },
            }
            if len(direct_rule_entries) == 1 and "pattern" in direct_rule_entries[0]:
                rule_direct["pattern"] = direct_rule_entries[0]["pattern"]
            else:
                rule_direct["pattern-either"] = direct_rule_entries
            generated_rules.append(rule_direct)

    # 2. Package Import Rule (-import)
    import_patterns = []
    if ecosystem == "npm":
        for quoted in _quoted_variants(base_pkg):
            import_patterns.extend([
                # CommonJS
                {"pattern": f"require({quoted})"},
                # ESM default import:   import React from 'react'
                {"pattern": f"import $_ from {quoted}"},
                # ESM named imports:    import {{ fetch }} from 'undici'
                {"pattern": f"import {{...}} from {quoted}"},
                # ESM namespace import: import * as qs from 'qs'
                {"pattern": f"import * as $_ from {quoted}"},
                # ESM side-effect:      import 'pkg'
                {"pattern": f"import {quoted}"},
                # Dynamic import:       await import('pkg') / import('pkg')
                {"pattern": f"import({quoted})"},
            ])
    elif ecosystem == "pypi":
        import_patterns.extend([
            {"pattern": f"import {base_pkg}"},
            {"pattern": f"import {base_pkg} as ..."},
            {"pattern": f"from {base_pkg} import ..."},
        ])
    else: # Generic JS/TS/Py
        import_patterns.extend([
            {"pattern": f"import {base_pkg}"},
            {"pattern": f"require('{base_pkg}')"},
            {"pattern": f"import ... from '{base_pkg}'"},
            {"pattern": f"from {base_pkg} import ..."},
        ])
        
    if import_patterns:
        rule_import: Dict[str, Any] = {
            "id": f"{base_id}-import",
            "message": f"{vuln_id}: vulnerable package '{pkg}' imported but code paths may vary",
            "severity": "INFO",
            "languages": languages,
            "metadata": {
                "vuln_id": vuln_id,
                "package": pkg,
                "tier": "import",
                "sink_quality": sink_quality,
            },
        }
        rule_import["pattern-either"] = import_patterns
        generated_rules.append(rule_import)

    return generated_rules


def generate_rules(sinks_by_vuln: Dict[str, List[Dict]], tmp_dir: Path) -> Path:
    """
    Write a single semgrep rules YAML file for all sinks.
    Returns path to the generated file.
    """
    seen_ids: set = set()
    rules = []
    for vuln_id, sinks in sinks_by_vuln.items():
        for sink in sinks:
            new_rules = _make_rules(sink)
            for rule in new_rules:
                if rule["id"] not in seen_ids:
                    seen_ids.add(rule["id"])
                    rules.append(rule)

    rules_file = tmp_dir / "sbom_reach_rules.yaml"
    with open(rules_file, "w", encoding="utf-8") as f:
        yaml.dump(
            {"rules": rules},
            f,
            Dumper=_ReadableYamlDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=1000,
        )

    logger.debug(f"Generated {len(rules)} Semgrep rules → {rules_file}")
    return rules_file


# ---------------------------------------------------------------------------
# Semgrep runner
# ---------------------------------------------------------------------------

def _resolve_semgrep() -> Optional[List[str]]:
    """Return the semgrep invocation to use, or None if unavailable."""
    import sys
    if shutil.which("semgrep"):
        return ["semgrep"]
    # Windows: pip installs to user Scripts dir which may not be in PATH
    scripts = Path(sys.executable).parent / "Scripts" / "semgrep.exe"
    if scripts.exists():
        return [str(scripts)]
    # Last resort: python -m semgrep (deprecated but works)
    try:
        r = subprocess.run(
            [sys.executable, "-m", "semgrep", "--version"],
            capture_output=True, timeout=15,
        )
        if r.returncode == 0 or b"deprecated" in r.stderr:
            return [sys.executable, "-m", "semgrep"]
    except Exception:
        pass
    return None


def run_semgrep(rules_file: Path, repo_path: str,
                timeout: int = 120) -> List[Dict[str, Any]]:
    """
    Run semgrep and return raw findings list.
    Returns empty list if semgrep is not installed or scan fails.
    """
    semgrep_cmd = _resolve_semgrep()
    if not semgrep_cmd:
        logger.error("semgrep not found. Install with: pip install semgrep")
        return []

    cmd = semgrep_cmd + [
        "--config", str(rules_file),
        "--json",
        "--no-git-ignore",
        str(repo_path),
    ]

    logger.debug(f"[Semgrep] CMD: {' '.join(str(c) for c in cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        # logger.debug(f"[Semgrep] Exit={result.returncode}")
        # logger.debug(f"[Semgrep] stderr: {result.stderr[:600] if result.stderr else '(empty)'}")
        if result.stdout:
            data = json.loads(result.stdout)
            # logger.debug(f"[Semgrep] errors: {data.get('errors', [])[:3]}")
            # logger.debug(f"[Semgrep] paths scanned: {len(data.get('paths', {}).get('scanned', []))}")
            return data.get("results", [])
        logger.warning(f"[Semgrep] No stdout. Exit={result.returncode}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep timed out after {timeout}s on {repo_path}")
        return []
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Semgrep run failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Result parser
# ---------------------------------------------------------------------------

def parse_findings(
    findings: List[Dict[str, Any]],
    sinks_by_vuln: Dict[str, List[Dict]],
    vuln_ids: List[str],
    repo_path: str = "",
) -> List[ReachabilityResult]:
    """
    Convert raw semgrep findings to ReachabilityResult list.
    One result per (vuln_id, sink_function).
    """
    # Aggregate findings by rule_id
    hits: Dict[str, List[str]] = {}  # rule_id → ["file:line", ...]
    for finding in findings:
        check_id = finding.get("check_id", "")
        # Semgrep prefixes rule IDs with the config file path (dot-separated).
        if "sbom-reach-" in check_id:
            rule_id = "sbom-reach-" + check_id.split("sbom-reach-", 1)[1]
        else:
            rule_id = check_id
        path = finding.get("path", "")
        if repo_path:
            norm_repo = repo_path.replace("\\", "/").rstrip("/")
            norm_path = path.replace("\\", "/")
            if norm_path.startswith(norm_repo + "/"):
                path = norm_path[len(norm_repo) + 1:]
            else:
                path = norm_path
        line = finding.get("start", {}).get("line", "")
        loc = f"{path}:{line}" if line else path
        hits.setdefault(rule_id, []).append(loc)

    results: List[ReachabilityResult] = []
    seen = set()

    # Build results for every sink (evaluate all auto-generated tiered rules)
    for vuln_id, sinks in sinks_by_vuln.items():
        for sink in sinks:
            rules = _make_rules(sink)
            if not rules:
                continue

            pkg = sink.get("package_name", "")
            fn = sink.get("function_name")
            key = (vuln_id, fn)
            if key in seen:
                continue
            seen.add(key)

            direct_locations = []
            import_locations = []
            sink_quality = "strong"   # default; overridden below from metadata
            for r in rules:
                meta = r.get("metadata", {})
                tier = meta.get("tier", "")
                locs = hits.get(r["id"], [])
                if tier == "direct":
                    direct_locations.extend(locs)
                    # Pick up the quality tag written by _make_rules()
                    sink_quality = meta.get("sink_quality", sink_quality)
                elif tier == "import":
                    import_locations.extend(locs)

            if direct_locations:
                # A "generic" quality sink matched via import-aware contextual
                # patterns — still strong evidence because provenance is required,
                # but we cap at confirmed_reachable only for non-generic sinks to
                # be conservative. Generic matches stay confirmed_reachable too,
                # because the contextual patterns already enforce import provenance;
                # the earlier FPs came from RAW patterns which are now suppressed.
                verdict = "confirmed_reachable"
                score = 1.0
                locations = direct_locations
                sink_label = fn or pkg
                evidence = (
                    f"Direct package API usage confirmed: '{sink_label}' matched "
                    f"in {len(locations)} location(s) with import provenance."
                )
            elif import_locations:
                verdict = "likely_reachable"
                score = 0.7
                locations = import_locations
                evidence = (
                    f"Package '{pkg}' is imported in {len(locations)} location(s) "
                    f"but direct sink call was not observed — may be wrapper-mediated."
                )
            else:
                verdict = "likely_unreachable"
                score = 0.3
                locations = []
                evidence = (
                    "Semgrep searched for both direct calls and package imports — "
                    "no matches found in the scanned repository."
                )

            results.append(ReachabilityResult(
                vuln_id=vuln_id,
                package_name=sink["package_name"],
                sink_function=fn,
                verdict=verdict,
                reach_score=score,
                call_locations=locations,
                semgrep_rule_id=rules[0]["id"],
                evidence=evidence,
            ))

    # Vulns with no sinks in DB → no_sink_data
    all_covered = {r.vuln_id for r in results}
    for vuln_id in vuln_ids:
        if vuln_id not in all_covered:
            results.append(ReachabilityResult(
                vuln_id=vuln_id,
                package_name="",
                sink_function=None,
                verdict="no_sink_data",
                reach_score=0.5,
                evidence="No sink data in cve_sinks.db for this CVE.",
            ))

    return results


# ---------------------------------------------------------------------------
# Main agent class
# ---------------------------------------------------------------------------

class SemgrepAgent:
    """
    Phase 2 reachability agent using Semgrep.

    Usage::

        agent = SemgrepAgent(project_name="owner/repo", repo_path="/wsl/path/to/repo")
        results = agent.scan(vuln_ids)
        agent.save(results)
    """

    def __init__(self, project_name: str, repo_path: str):
        self.project_name = project_name
        self.repo_path = repo_path

    def scan(self, vuln_ids: List[str]) -> List[ReachabilityResult]:
        """
        Full scan: load sinks → gen rules → run semgrep → parse results.
        """
        if not vuln_ids:
            logger.warning("No vuln_ids provided to SemgrepAgent.scan()")
            return []

        # 1. Load sinks from DB
        sinks_by_vuln = get_sinks_for_vulns(vuln_ids)
        sinks_found = sum(len(v) for v in sinks_by_vuln.values())
        sinks_missing = len([v for v in vuln_ids if not sinks_by_vuln.get(v)])
        logger.info(f"[Semgrep] Loaded {sinks_found} sinks for {len(vuln_ids)} vulns "
                    f"({sinks_missing} vulns have no sink data)")

        if sinks_found == 0:
            logger.warning("[Semgrep] No sinks found in DB — all results will be 'no_sink_data'")
            return [
                ReachabilityResult(
                    vuln_id=v, package_name="", sink_function=None,
                    verdict="no_sink_data", reach_score=0.5,
                    evidence="No sink data in cve_sinks.db.",
                )
                for v in vuln_ids
            ]

        # 2. Generate rules in temp dir, persist to data/rules/ for reference
        with tempfile.TemporaryDirectory(prefix="sbom_semgrep_") as tmp:
            tmp_path = Path(tmp)
            rules_file = generate_rules(sinks_by_vuln, tmp_path)
            rule_count = sum(
                len(_make_rules(s))
                for s in (s for sinks in sinks_by_vuln.values() for s in sinks)
            )
            logger.info(f"[Semgrep] Generated {rule_count} rules → running scan on {self.repo_path}")

            # Persist rules YAML for reference
            _RULES_DIR.mkdir(parents=True, exist_ok=True)
            safe = self.project_name.replace("/", "_").replace("\\", "_")
            saved_rules = _RULES_DIR / f"{safe}_rules.yaml"
            shutil.copy2(rules_file, saved_rules)
            logger.info(f"[Semgrep] Rules saved → {saved_rules}")

            # 3. Run semgrep
            findings = run_semgrep(rules_file, self.repo_path)
            logger.info(f"[Semgrep] Found {len(findings)} raw finding(s)")

            # 4. Parse
            results = parse_findings(findings, sinks_by_vuln, vuln_ids, self.repo_path)

        reachable = sum(1 for r in results if r.verdict == "confirmed_reachable")
        unreachable = sum(1 for r in results if r.verdict == "likely_unreachable")
        no_data = sum(1 for r in results if r.verdict == "no_sink_data")
        logger.info(
            f"[Semgrep] Results: {reachable} reachable, "
            f"{unreachable} unreachable, {no_data} no_sink_data"
        )
        return results

    def save(self, results: List[ReachabilityResult],
             also_save_json: bool = True) -> Path:
        """
        Persist results to:
          - cve_sinks.db (reachability_results table)
          - data/reachability/{safe_project}.json
        """
        # Save to SQLite
        rows = [r.to_dict() for r in results]
        save_reachability(self.project_name, rows)

        if not also_save_json:
            return _REACH_DIR

        # Save to JSON
        _REACH_DIR.mkdir(parents=True, exist_ok=True)
        safe = self.project_name.replace("/", "_").replace("\\", "_")
        out_file = _REACH_DIR / f"{safe}_reachability.json"

        reachable = [r for r in results if r.verdict == "confirmed_reachable"]
        summary = {v: 0 for v in VERDICT_SCORES}
        for r in results:
            summary[r.verdict] = summary.get(r.verdict, 0) + 1

        payload = {
            "project": self.project_name,
            "repo_path": self.repo_path,
            "total_sinks_checked": len(results),
            "summary": summary,
            "reachable_count": len(reachable),
            "results": [r.to_dict() for r in results],
        }
        out_file.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        logger.info(f"[Semgrep] Saved → {out_file}")
        return out_file
