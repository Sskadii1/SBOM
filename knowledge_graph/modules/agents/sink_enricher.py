"""
knowledge_graph/modules/agents/sink_enricher.py

Offline CVE sink enrichment using OpenRouter (Gemini / GPT-4o) with tool use.

Supplements VulnIntelAgent by fetching richer context from:
  - GitHub commit diffs (.patch format) from OSV FIX references
  - GHSA advisory pages from OSV ADVISORY references

Targets CVEs that have verdict='no_sink_data' in reachability_results
but no entry in cve_sinks, and inserts extracted sinks into cve_sinks.db.

Usage:
    # Enrich up to 50 unenriched CVEs from reachability_results:
    python sink_enricher.py --limit 50

    # Enrich a specific CVE:
    python sink_enricher.py --cve CVE-2021-23369 --package lodash --ecosystem npm

    # Dry run (extract but do not write to DB):
    python sink_enricher.py --limit 100 --dry-run
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore

try:
    from dotenv import load_dotenv
    _kg_env = Path(__file__).resolve().parents[2] / ".env"
    _root_env = Path(__file__).resolve().parents[3] / ".env"
    for _p in (_kg_env, _root_env):
        if _p.exists():
            load_dotenv(dotenv_path=_p, override=True)
            break
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("sink_enricher")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OSV_API_BASE = "https://api.osv.dev/v1"
GHSA_API_BASE = "https://api.github.com/advisories"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Default model — change via --model or ENRICHER_MODEL env var
DEFAULT_MODEL = os.environ.get("ENRICHER_MODEL", "google/gemini-2.0-flash-exp:free")

MAX_PATCH_CHARS = 4000     # truncate .patch content
MAX_ADVISORY_CHARS = 3000  # truncate advisory text
MAX_TOOL_ROUNDS = 6        # max tool-use rounds per CVE
HTTP_TIMEOUT = 30          # seconds per HTTP request

# OSV ecosystem name → our schema name
_ECO_MAP = {
    "pypi": "pypi",
    "npm": "npm",
    "crates.io": "cargo",
    "maven": "maven",
    "go": "go",
    "rubygems": "gem",
    "nuget": "nuget",
    "packagist": "composer",
    "hex": "hex",
    "pub": "pub",
}

_PROMPT_PATH = Path(__file__).parent / "prompts" / "vuln_sink_extraction.md"

# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling format)
# ---------------------------------------------------------------------------
_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_github_patch",
            "description": (
                "Fetch the raw .patch diff for a GitHub commit. "
                "Returns function-context lines (@@ headers) and changed lines. "
                "Use this to see which functions were patched — those are likely the vulnerable sinks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "commit_url": {
                        "type": "string",
                        "description": "Full GitHub commit URL, e.g. https://github.com/owner/repo/commit/abc123",
                    }
                },
                "required": ["commit_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_advisory_page",
            "description": (
                "Fetch a GHSA advisory from the GitHub Advisory API, or any advisory URL as text. "
                "For GHSA URLs (github.com/advisories/GHSA-...), returns structured JSON "
                "(summary, severity, affected packages, references). "
                "For other URLs, returns a truncated text snippet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Advisory URL — GHSA (https://github.com/advisories/GHSA-...) or any web URL.",
                    }
                },
                "required": ["url"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: Optional[Dict[str, str]] = None) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header("User-Agent", "sink-enricher/1.0")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return f"[HTTP {e.code}] {e.reason}"
    except Exception as e:
        return f"[Error] {e}"


def _fetch_osv(vuln_id: str) -> Optional[Dict]:
    text = _http_get(f"{OSV_API_BASE}/vulns/{vuln_id}")
    try:
        return json.loads(text)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _tool_fetch_github_patch(commit_url: str, github_token: str = "") -> str:
    """Fetch .patch diff for a GitHub commit, return relevant lines only."""
    url = commit_url.split("?")[0].split("#")[0].rstrip("/")

    if "github.com" not in url or "/commit/" not in url:
        return f"[skip] Not a GitHub commit URL: {commit_url}"

    headers: Dict[str, str] = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    raw = _http_get(url + ".patch", headers=headers)
    if raw.startswith("[HTTP") or raw.startswith("[Error"):
        return raw

    # Keep only diff --git headers, @@ context lines, and changed lines
    kept = []
    for line in raw.splitlines():
        if line.startswith("diff --git") or line.startswith("@@"):
            kept.append(line)
        elif line.startswith("+") and not line.startswith("+++"):
            kept.append(line)
        elif line.startswith("-") and not line.startswith("---"):
            kept.append(line)

    result = "\n".join(kept)
    if len(result) > MAX_PATCH_CHARS:
        result = result[:MAX_PATCH_CHARS] + "\n... [truncated]"
    return result or "[empty patch]"


def _tool_fetch_advisory_page(url: str, github_token: str = "") -> str:
    """Fetch GHSA advisory via GitHub API, or generic advisory as text."""
    ghsa_match = re.search(r"GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+", url, re.IGNORECASE)
    if ghsa_match and "github.com/advisories" in url:
        ghsa_id = ghsa_match.group(0).upper()
        headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        text = _http_get(f"{GHSA_API_BASE}/{ghsa_id}", headers=headers)
        try:
            data = json.loads(text)
            out = {
                "ghsa_id": data.get("ghsa_id"),
                "summary": data.get("summary"),
                "description": (data.get("description") or "")[:1500],
                "severity": data.get("severity"),
                "cwes": data.get("cwes"),
                "affected": data.get("vulnerabilities", [])[:5],
                "references": [r.get("url") for r in (data.get("references") or [])[:10]],
            }
            text = json.dumps(out, indent=2)
        except Exception:
            pass
    else:
        text = _http_get(url)

    if len(text) > MAX_ADVISORY_CHARS:
        text = text[:MAX_ADVISORY_CHARS] + "\n... [truncated]"
    return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_ecosystem(raw: str) -> str:
    return _ECO_MAP.get(raw.lower().strip(), raw.lower().strip())


def _extract_references(osv_data: Dict) -> Tuple[List[str], List[str]]:
    """Return (commit_urls, advisory_urls) from OSV references field."""
    commit_urls: List[str] = []
    advisory_urls: List[str] = []
    for ref in osv_data.get("references", []):
        ref_type = ref.get("type", "").upper()
        ref_url = ref.get("url", "")
        if not ref_url:
            continue
        if ref_type == "FIX" and "github.com" in ref_url and "/commit/" in ref_url:
            commit_urls.append(ref_url)
        elif ref_type in ("ADVISORY", "REPORT") and (
            "github.com/advisories" in ref_url or "GHSA" in ref_url
        ):
            advisory_urls.append(ref_url)
    return commit_urls[:3], advisory_urls[:2]


def _parse_sinks(text: str, vuln_id: str, pkg: str, eco: str) -> List[Dict]:
    """Extract JSON array from LLM response and convert to DB-ready rows."""
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except Exception:
        return []

    rows = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        entry_vuln = entry.get("vuln_id") or vuln_id
        entry_pkg = entry.get("package") or pkg
        entry_eco = _normalize_ecosystem(entry.get("ecosystem") or eco)
        for sink in entry.get("sinks", []):
            fn = sink.get("function_name")
            if not fn:
                continue
            confidence = float(sink.get("confidence", 0.7))
            if confidence < 0.7:
                continue
            rows.append({
                "vuln_id": entry_vuln,
                "package_name": entry_pkg,
                "ecosystem": entry_eco,
                "function_name": fn,
                "class_name": sink.get("class_name"),
                "call_pattern": sink.get("call_pattern"),
                "sink_type": sink.get("sink_type", "function_call"),
                "vuln_type": sink.get("vuln_type", "other"),
                "confidence": confidence,
                "source": "ai_enriched",
                "raw_evidence": sink.get("note", ""),
            })
    return rows


def _dispatch_tool(name: str, arguments: Dict, github_token: str) -> str:
    """Execute a tool call and return the string result."""
    if name == "fetch_github_patch":
        return _tool_fetch_github_patch(arguments.get("commit_url", ""), github_token)
    elif name == "fetch_advisory_page":
        return _tool_fetch_advisory_page(arguments.get("url", ""), github_token)
    return f"[unknown tool: {name}]"


# ---------------------------------------------------------------------------
# DB helpers (standalone — no circular imports when run as __main__)
# ---------------------------------------------------------------------------

def _get_db_path() -> Path:
    default = Path(__file__).resolve().parents[2] / "data" / "cve_sinks.db"
    return Path(os.environ.get("CVE_SINKS_DB", str(default)))


def _query_unenriched(db_path: Path, limit: int) -> List[Tuple[str, str]]:
    """
    Return (vuln_id, package_name) pairs that have verdict='no_sink_data'
    in reachability_results but no row in cve_sinks yet.
    """
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT DISTINCT rr.vuln_id, rr.package_name
            FROM reachability_results rr
            WHERE rr.verdict = 'no_sink_data'
              AND NOT EXISTS (
                  SELECT 1 FROM cve_sinks cs WHERE cs.vuln_id = rr.vuln_id
              )
            ORDER BY rr.scanned_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [(r["vuln_id"], r["package_name"]) for r in rows]
    finally:
        con.close()


def _insert_sinks(db_path: Path, sinks: List[Dict]) -> int:
    """Insert sinks, ignoring UNIQUE conflicts. Returns rows inserted."""
    if not sinks:
        return 0
    cols = [
        "vuln_id", "package_name", "ecosystem", "function_name", "class_name",
        "call_pattern", "sink_type", "vuln_type", "confidence", "source", "raw_evidence",
    ]
    placeholders = ",".join("?" * len(cols))
    col_str = ",".join(cols)
    inserted = 0
    con = sqlite3.connect(str(db_path))
    try:
        for s in sinks:
            cur = con.execute(
                f"INSERT OR IGNORE INTO cve_sinks ({col_str}) VALUES ({placeholders})",
                [s.get(c) for c in cols],
            )
            inserted += cur.rowcount
        con.commit()
    finally:
        con.close()
    return inserted


# ---------------------------------------------------------------------------
# SinkEnricher
# ---------------------------------------------------------------------------

class SinkEnricher:
    """
    Offline enrichment agent using OpenRouter (Gemini / GPT-4o) with function calling
    to extract sinks from GitHub commit patches and GHSA advisories.
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = DEFAULT_MODEL,
        github_token: str = "",
        db_path: Optional[Path] = None,
        base_url: str = OPENROUTER_BASE_URL,
    ):
        if OpenAI is None:
            raise ImportError("openai package is required: pip install openai")

        resolved_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        if not resolved_key:
            raise ValueError("OPENROUTER_API_KEY is required (set env var or pass api_key)")

        self.client = OpenAI(api_key=resolved_key, base_url=base_url)
        self.model = model
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.db_path = db_path or _get_db_path()
        self._system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")

    # ------------------------------------------------------------------
    # Batch mode
    # ------------------------------------------------------------------

    def run(self, limit: int = 50, dry_run: bool = False) -> Dict[str, Any]:
        """
        Enrich up to `limit` CVEs that have no_sink_data in reachability_results.
        Returns summary dict.
        """
        targets = _query_unenriched(self.db_path, limit)
        if not targets:
            logger.info("No unenriched CVEs found in reachability_results.")
            return {"processed": 0, "inserted": 0, "failed": 0}

        logger.info(f"Found {len(targets)} unenriched CVEs.")
        total_inserted = 0
        failed = 0

        for vuln_id, pkg in targets:
            try:
                logger.info(f"Enriching {vuln_id} / {pkg or '(unknown pkg)'}")
                sinks = self.enrich_single(vuln_id, pkg)
                logger.info(f"  -> {len(sinks)} sink(s) extracted")

                if sinks and not dry_run:
                    n = _insert_sinks(self.db_path, sinks)
                    total_inserted += n
                    logger.info(f"  -> {n} inserted into DB")
                elif dry_run and sinks:
                    logger.info(f"  [dry-run] would insert:\n{json.dumps(sinks, indent=2)}")

            except Exception as e:
                logger.warning(f"  Failed for {vuln_id}: {e}")
                failed += 1

            time.sleep(1)  # brief pause between CVEs

        return {"processed": len(targets), "inserted": total_inserted, "failed": failed}

    # ------------------------------------------------------------------
    # Single CVE enrichment
    # ------------------------------------------------------------------

    def enrich_single(
        self,
        vuln_id: str,
        package_name: str,
        ecosystem: str = "",
    ) -> List[Dict]:
        """
        Enrich one CVE. Fetches OSV data, runs LLM agent loop with tools,
        returns list of sink dicts ready for insert_sinks().
        """
        osv_data = _fetch_osv(vuln_id)
        if not osv_data:
            logger.warning(f"Cannot fetch OSV data for {vuln_id}")
            return []

        # Recover package_name / ecosystem from OSV when Neo4j c.name is empty.
        # Standard ECOSYSTEM entries have affected[].package.name.
        # GIT-only entries omit the package field — infer name from repo URL.
        for affected in osv_data.get("affected", []):
            pkg_info = affected.get("package", {})
            osv_pkg = pkg_info.get("name", "")
            if osv_pkg:
                if not package_name:
                    package_name = osv_pkg
                if not ecosystem:
                    ecosystem = _normalize_ecosystem(pkg_info.get("ecosystem", ""))
                break
            # GIT-range only — no package field
            if not package_name:
                for rng in affected.get("ranges", []):
                    if rng.get("type") == "GIT":
                        repo = rng.get("repo", "").rstrip("/")
                        if repo:
                            package_name = repo.split("/")[-1]
                        break
            if package_name:
                break

        if not package_name:
            logger.warning(f"Cannot determine package name for {vuln_id} — skipping")
            return []

        summary = osv_data.get("summary", "")
        details = osv_data.get("details", "")
        aliases = osv_data.get("aliases", [])
        commit_urls, advisory_urls = _extract_references(osv_data)

        # Build initial context message
        parts = [
            f"CVE: {vuln_id}",
            f"Package: {package_name}",
            f"Ecosystem: {ecosystem or 'unknown'}",
        ]
        if aliases:
            parts.append(f"Aliases: {', '.join(aliases)}")
        if summary:
            parts.append(f"\nSummary:\n{summary}")
        if details:
            parts.append(f"\nDetails:\n{details[:2000]}")

        ref_lines = []
        if commit_urls:
            ref_lines.append("Commit patches (fetch for patched function names):")
            ref_lines.extend(f"  {u}" for u in commit_urls)
        if advisory_urls:
            ref_lines.append("Advisory pages (fetch for fuller description):")
            ref_lines.extend(f"  {u}" for u in advisory_urls)
        if ref_lines:
            parts.append("\nAvailable references — use tools to fetch them:\n" + "\n".join(ref_lines))

        parts.append(
            "\nUsing the above information and any references you fetch, "
            "extract the vulnerable sink(s). Return ONLY a JSON array per the system prompt schema."
        )

        messages = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": "\n".join(parts)},
        ]
        return self._run_agent_loop(messages, vuln_id, package_name, ecosystem)

    # ------------------------------------------------------------------
    # Agentic tool-use loop (OpenAI function-calling format)
    # ------------------------------------------------------------------

    def _run_agent_loop(
        self,
        messages: List[Dict],
        vuln_id: str,
        pkg: str,
        eco: str,
    ) -> List[Dict]:
        tool_rounds = 0

        while tool_rounds <= MAX_TOOL_ROUNDS:
            response = self.client.chat.completions.create(
                model=self.model,
                tools=_TOOLS,
                tool_choice="auto",
                max_tokens=2048,
                messages=messages,
            )
            msg = response.choices[0].message
            finish_reason = response.choices[0].finish_reason

            # Append assistant message (preserve tool_calls if present)
            assistant_msg: Dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ]
            messages.append(assistant_msg)

            if finish_reason == "stop" or not msg.tool_calls:
                return _parse_sinks(msg.content or "", vuln_id, pkg, eco)

            # Execute tool calls
            for tc in msg.tool_calls:
                tool_rounds += 1
                try:
                    arguments = json.loads(tc.function.arguments)
                except Exception:
                    arguments = {}
                logger.debug(f"  Tool: {tc.function.name}({arguments})")
                result = _dispatch_tool(tc.function.name, arguments, self.github_token)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

        # Hit round limit — ask for final answer without tools
        logger.warning(f"Reached tool round limit for {vuln_id}, requesting final answer.")
        messages.append({
            "role": "user",
            "content": "Based on all information gathered, return the final JSON array now.",
        })
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=2048,
            messages=messages,
        )
        text = response.choices[0].message.content or ""
        return _parse_sinks(text, vuln_id, pkg, eco)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Offline CVE sink enrichment using OpenRouter (Gemini / GPT-4o).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Models (via OpenRouter):
  google/gemini-2.0-flash-exp:free      (default, free)
  google/gemini-2.0-flash-001           (paid, faster)
  openai/gpt-4o-mini                    (paid)
  openai/gpt-4o                         (paid)
  anthropic/claude-sonnet-4-6           (paid)

Examples:
  # Enrich up to 50 unenriched CVEs from reachability_results:
  python sink_enricher.py --limit 50

  # Use GPT-4o instead of Gemini:
  python sink_enricher.py --limit 50 --model openai/gpt-4o

  # Enrich a specific CVE (no DB query needed):
  python sink_enricher.py --cve CVE-2026-2229 --package undici --ecosystem npm --dry-run

  # Dry run:
  python sink_enricher.py --limit 100 --dry-run
        """,
    )
    p.add_argument("--cve", help="Specific CVE ID to enrich")
    p.add_argument("--package", "-p", help="Package name (required with --cve)")
    p.add_argument("--ecosystem", "-e", help="Ecosystem (npm|pypi|cargo|...)")
    p.add_argument("--limit", "-n", type=int, default=50,
                   help="Max CVEs to process from DB (default: 50)")
    p.add_argument("--dry-run", action="store_true",
                   help="Extract sinks but do not write to DB")
    p.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"OpenRouter model (default: {DEFAULT_MODEL})")
    p.add_argument("--db", help="Path to cve_sinks.db (overrides CVE_SINKS_DB env)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> None:
    args = _build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    db_path = Path(args.db) if args.db else _get_db_path()

    enricher = SinkEnricher(model=args.model, db_path=db_path)

    if args.cve:
        if not args.package:
            print("Error: --package is required with --cve")
            raise SystemExit(1)
        sinks = enricher.enrich_single(
            vuln_id=args.cve,
            package_name=args.package,
            ecosystem=args.ecosystem or "",
        )
        print(f"\nExtracted {len(sinks)} sink(s):")
        print(json.dumps(sinks, indent=2))
        if sinks and not args.dry_run:
            n = _insert_sinks(db_path, sinks)
            print(f"Inserted {n} row(s) into {db_path}")
    else:
        result = enricher.run(limit=args.limit, dry_run=args.dry_run)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
