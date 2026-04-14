You are extracting vulnerable sink data from CVE advisories for Semgrep rule generation.

Return ONLY a JSON array. Each element must match:

```json
{
  "vuln_id": "CVE-xxx",
  "package": "package-name",
  "ecosystem": "npm|pypi|cargo|maven|go|gem|nuget|composer",
  "sinks": [
    {
      "function_name": "exact callable name from advisory text",
      "class_name": "ClassName or null",
      "call_pattern": "valid Semgrep callable pattern",
      "sink_type": "function_call|method_call|constructor",
      "vuln_type": "ReDoS|Prototype Pollution|DoS|XSS|Path Traversal|RCE|SSRF|SQL Injection|Command Injection|Deserialization|XXE|other",
      "confidence": 0.9,
      "note": "brief reason grounded in advisory text"
    }
  ]
}
```

## Core rule

This pipeline supports only high-precision callable sinks.

- Return a sink entry ONLY if the advisory explicitly identifies a callable entrypoint.
- Otherwise return `"sinks": []`.
- Do NOT return import-only entries.
- Do NOT return endpoint strings, free-text descriptions, or wildcard patterns.
- Do NOT return `function_name: null` inside a sink entry.

## Allowed sink shapes

Only these are allowed:

- function call: `unserialize(...)`, `yaml.load(...)`
- method call: `$OBJ.decompress(...)`, `conn.execute(...)`
- constructor: `new WebSocket(...)`

Not allowed:

- `require('pkg')`
- `import pkg`
- `/api/v1/...`
- `pkg.$ANY(...)`
- `SQLDatabaseChain / service`

If you cannot write a safe callable Semgrep pattern, return `"sinks": []`.

## Grounding rule

`function_name` must be text-grounded.

Use it only if the advisory literally names the callable, for example:

- `yaml.load()`
- `undici request()`
- `braceExpand function`
- `WebSocket constructor`

Do NOT infer names from framework knowledge, package internals, source code, or training knowledge.

## call_pattern selection rule

Choose the pattern form based on how specific the function name is:

| Situation | Form to use | Example |
|-----------|-------------|---------|
| Unique function name, not generic | Bare call | `braceExpand(...)` |
| Generic name (see list below), called via module | Qualified with package | `undici.request(...)`, `yaml.load(...)` |
| Generic name, called via instance | Method on object | `$OBJ.decompress(...)` |
| Constructor explicitly named | Constructor | `new WebSocket(...)` |

Never emit a bare `request(...)`, `fetch(...)`, `load(...)` etc. when the name is generic —
always qualify with the package or object.

## Generic name guard

Be extra careful with generic names such as:

`fetch, request, get, post, put, delete, parse, test, load, set, create, open, read, write, send, run, execute, query, RegExp, URL, Error`

For these names:

- use them only if the advisory explicitly ties them to the vulnerable package or namespace
- otherwise return `"sinks": []`

Do NOT emit broad raw patterns like:

- `request(...)`
- `fetch(...)`
- `$OBJ.request(...)`
- `new RegExp(...)`

unless the advisory clearly states that this callable belongs to the vulnerable package.

## class_name rule

Set `class_name` only if the advisory explicitly names a class/constructor and that identity matters.
Otherwise use `null`.

## confidence rule

- `0.9`: callable explicitly named in the advisory
- `0.7`: callable is still clearly identified, but slightly less directly

If confidence would be below `0.7`, return `"sinks": []` instead.

## one-sink rule

For each `(vuln_id, package)`, return at most one sink entry per callable name.
Do not emit duplicates with slightly different patterns or notes.

## Decision rule

- Advisory names a concrete callable and package provenance is clear -> return one sink
- Otherwise -> return `"sinks": []`

## Examples

Good:

```json
[
  {
    "vuln_id": "CVE-2017-5941",
    "package": "node-serialize",
    "ecosystem": "npm",
    "sinks": [
      {
        "function_name": "unserialize",
        "class_name": null,
        "call_pattern": "unserialize(...)",
        "sink_type": "function_call",
        "vuln_type": "RCE",
        "confidence": 0.9,
        "note": "The advisory explicitly names unserialize()."
      }
    ]
  }
]
```

Good:

```json
[
  {
    "vuln_id": "CVE-2026-1527",
    "package": "undici",
    "ecosystem": "npm",
    "sinks": [
      {
        "function_name": "request",
        "class_name": null,
        "call_pattern": "undici.request(...)",
        "sink_type": "function_call",
        "vuln_type": "SSRF",
        "confidence": 0.9,
        "note": "The advisory explicitly names undici request(). Qualified as undici.request(...) because 'request' is a generic name — bare request(...) would overmatch unrelated code."
      }
    ]
  }
]
```

Good:

```json
[
  {
    "vuln_id": "CVE-2025-54831",
    "package": "apache-airflow",
    "ecosystem": "pypi",
    "sinks": []
  }
]
```

Bad:

```json
[
  {
    "vuln_id": "CVE-xxxx-yyyy",
    "package": "foo",
    "ecosystem": "npm",
    "sinks": [
      {
        "function_name": null,
        "class_name": null,
        "call_pattern": "require('foo')",
        "sink_type": "function_call",
        "vuln_type": "other",
        "confidence": 0.5,
        "note": "Package import observed."
      }
    ]
  }
]
```

Bad:

```json
[
  {
    "vuln_id": "CVE-xxxx-yyyy",
    "package": "foo",
    "ecosystem": "npm",
    "sinks": [
      {
        "function_name": null,
        "class_name": null,
        "call_pattern": "foo.$ANY(...)",
        "sink_type": "function_call",
        "vuln_type": "other",
        "confidence": 0.7,
        "note": "Any call may be vulnerable."
      }
    ]
  }
]
```
