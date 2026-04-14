"""
modules/agents/vuln_intel_agent.py - Agent 1: Vulnerability Intelligence Agent.

Responsibilities
~~~~~~~~~~~~~~~~
1. Read CVE/vulnerability data from Neo4j (or local JSON).
2. Fetch full OSV advisory detail for each vulnerability.
3. Extract **vulnerable sinks** (function, class, file pattern) via:
   a. Structured fields in OSV (`affected[].ecosystem_specific.affected_functions`)
   b. LLM-based extraction from advisory text when structured data is missing.
4. Return a list of VulnSink objects with confidence scores.
"""

import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

try:
    from modules.agents import config as agent_config
    from modules.agents.rate_limiter import RateLimiter
except ModuleNotFoundError:
    KG_ROOT = Path(__file__).resolve().parents[2]
    if str(KG_ROOT) not in sys.path:
        sys.path.insert(0, str(KG_ROOT))
    from modules.agents import config as agent_config
    from modules.agents.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VulnSink:
    """A single vulnerable code sink identified from an advisory."""
    vuln_id: str                          # CVE-2024-XXXX or GHSA-...
    package_name: str                     # e.g. "minimatch"
    ecosystem: str = ""                   # e.g. "npm"
    function_name: Optional[str] = None   # e.g. "braceExpand"
    class_name: Optional[str] = None      # e.g. "Minimatch"
    call_pattern: Optional[str] = None    # e.g. "braceExpand(...)"
    sink_type: Optional[str] = None       # e.g. "function_call"
    vuln_type: str = ""                   # e.g. "ReDoS", "Prototype Pollution", "XSS"
    confidence: float = 0.0              # 0.0 - 1.0
    source: str = ""                      # "osv_structured" | "llm_extraction" | "cwe_heuristic"
    raw_evidence: str = ""                # The text/data used to derive this sink

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VulnIntelResult:
    """Result for one vulnerability: all identified sinks + metadata."""
    vuln_id: str
    osv_id: Optional[str] = None
    summary: str = ""
    cwe: str = ""
    sinks: List[VulnSink] = field(default_factory=list)
    raw_advisory: Optional[Dict] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sinks"] = [s.to_dict() for s in self.sinks]
        return d


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------

class VulnIntelAgent:
    """
    Agent 1: Extracts vulnerable sinks from OSV/NVD advisories.

    Usage::

        agent = VulnIntelAgent()
        results = agent.analyze_vulnerabilities(vuln_list)
        # vuln_list = [{"vuln_id": "CVE-...", "package_name": "minimatch", ...}, ...]
    """

    def __init__(
        self,
        openrouter_api_key: str = "",
        llm_model: str = "",
        llm_temperature: float = 0.1,
        llm_max_tokens: int = 2048,
    ):
        self.api_key = openrouter_api_key or agent_config.OPENROUTER_API_KEY
        self.llm_model = llm_model or agent_config.LLM_MODEL
        self.llm_temperature = llm_temperature
        self.llm_max_tokens = llm_max_tokens

        self.osv_base = agent_config.OSV_API_BASE
        self._osv_cache: Dict[str, Dict] = {}

        # Rate limiters — one per external endpoint
        self._osv_limiter = RateLimiter(
            calls_per_second=agent_config.OSV_RATE_LIMIT_RPS,
            name="osv",
        )
        self._llm_limiter = RateLimiter(
            calls_per_second=agent_config.LLM_RATE_LIMIT_RPS,
            name="llm",
        )

        # Load LLM prompt template
        self._prompt_template = self._load_prompt_template()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_vulnerabilities(
        self,
        vuln_list: List[Dict[str, Any]],
    ) -> List[VulnIntelResult]:
        """
        Analyze a list of vulnerabilities and extract sinks.

        Parameters
        ----------
        vuln_list : list of dict
            Each dict should have at minimum:
              - vuln_id: str  (CVE-... or GHSA-...)
              - package_name: str
            Optional fields: cwe, aliases, summary, detail_summary

        Returns
        -------
        list of VulnIntelResult
        """
        results: List[VulnIntelResult] = []

        for vuln_info in vuln_list:
            vuln_id = vuln_info.get("vuln_id") or vuln_info.get("id") or ""
            if not vuln_id:
                continue

            logger.info(f"[VulnIntel] Analyzing {vuln_id} ...")
            result = self._analyze_single(vuln_info)
            results.append(result)

        logger.info(f"[VulnIntel] Analyzed {len(results)} vulnerabilities, "
                     f"found {sum(len(r.sinks) for r in results)} sinks total")
        return results

    # ------------------------------------------------------------------
    # Internal: single vulnerability analysis
    # ------------------------------------------------------------------

    def _analyze_single(self, vuln_info: Dict[str, Any]) -> VulnIntelResult:
        vuln_id = vuln_info.get("vuln_id") or vuln_info.get("id") or ""
        package_name = vuln_info.get("package_name") or vuln_info.get("component") or ""
        ecosystem = vuln_info.get("ecosystem") or vuln_info.get("eco") or ""
        cwe = vuln_info.get("cwe") or ""

        result = VulnIntelResult(
            vuln_id=vuln_id,
            cwe=cwe,
            summary=vuln_info.get("summary") or vuln_info.get("detail_summary") or "",
        )

        # Step 1: Fetch OSV advisory
        osv_data = self._fetch_osv_advisory(vuln_id, vuln_info.get("aliases"))
        result.raw_advisory = osv_data

        if osv_data:
            result.osv_id = osv_data.get("id")
            result.summary = result.summary or osv_data.get("summary", "")

        # Step 2: Try structured extraction from OSV affected_functions
        structured_sinks = self._extract_structured_sinks(osv_data, vuln_id, package_name)
        if structured_sinks:
            result.sinks.extend(structured_sinks)
            logger.info(f"  [OSV structured] Found {len(structured_sinks)} sink(s)")

        # Step 3: LLM extraction if structured data insufficient
        if not structured_sinks or all(s.confidence < 0.7 for s in structured_sinks):
            llm_sinks = self._extract_sinks_via_llm(
                vuln_id=vuln_id,
                package_name=package_name,
                ecosystem=ecosystem,
                cwe=cwe,
                summary=result.summary,
                details=osv_data.get("details", "") if osv_data else "",
                aliases=osv_data.get("aliases", []) if osv_data else [],
            )
            if llm_sinks:
                result.sinks.extend(llm_sinks)
                logger.info(f"  [LLM extraction] Found {len(llm_sinks)} sink(s)")

        # Deduplicate sinks by function_name
        result.sinks = self._deduplicate_sinks(result.sinks)

        if not result.sinks:
            logger.warning(f"  [VulnIntel] No sinks found for {vuln_id}")

        return result

    # ------------------------------------------------------------------
    # OSV advisory fetching
    # ------------------------------------------------------------------

    def _fetch_osv_advisory(
        self,
        vuln_id: str,
        aliases: Optional[List[str]] = None,
    ) -> Optional[Dict]:
        """Fetch full OSV advisory. Try vuln_id first, then aliases."""
        ids_to_try = [vuln_id]
        if aliases:
            ids_to_try.extend(aliases)

        for vid in ids_to_try:
            if not vid:
                continue
            if vid in self._osv_cache:
                return self._osv_cache[vid]

            try:
                url = f"{self.osv_base}/vulns/{vid}"

                def _do_osv_get() -> requests.Response:
                    r = requests.get(url, timeout=15)
                    r.raise_for_status()
                    return r

                resp = self._osv_limiter.call_with_retry(
                    _do_osv_get,
                    max_retries=agent_config.RATE_LIMIT_MAX_RETRIES,
                )
                data = resp.json()
                self._osv_cache[vid] = data
                return data
            except requests.HTTPError as e:
                logger.debug(f"  OSV fetch HTTP error for {vid}: {e}")
            except requests.RequestException as e:
                logger.debug(f"  OSV fetch failed for {vid}: {e}")

        return None

    # ------------------------------------------------------------------
    # Structured extraction from OSV affected_functions
    # ------------------------------------------------------------------

    def _extract_structured_sinks(
        self,
        osv_data: Optional[Dict],
        vuln_id: str,
        package_name: str,
    ) -> List[VulnSink]:
        """
        Extract sinks from OSV `affected[].ecosystem_specific` or
        `affected[].database_specific` fields.
        """
        if not osv_data:
            return []

        sinks: List[VulnSink] = []

        for affected in osv_data.get("affected", []):
            pkg = affected.get("package", {})
            pkg_name = pkg.get("name", "")

            # ecosystem_specific.affected_functions (Go, some npm)
            eco_specific = affected.get("ecosystem_specific", {}) or {}
            affected_funcs = eco_specific.get("affected_functions", []) or []

            for func in affected_funcs:
                sinks.append(VulnSink(
                    vuln_id=vuln_id,
                    package_name=pkg_name or package_name,
                    function_name=self._extract_function_name(func),
                    module_path=self._extract_module_path(func),
                    sink_description=f"OSV-listed affected function: {func}",
                    confidence=0.9,
                    source="osv_structured",
                    raw_evidence=func,
                ))

            # database_specific may also have function-level info
            db_specific = affected.get("database_specific", {}) or {}
            for key in ("affected_functions", "affected_methods", "vulnerable_functions"):
                for func in db_specific.get(key, []) or []:
                    sinks.append(VulnSink(
                        vuln_id=vuln_id,
                        package_name=pkg_name or package_name,
                        function_name=self._extract_function_name(func),
                        module_path=self._extract_module_path(func),
                        sink_description=f"OSV database_specific {key}: {func}",
                        confidence=0.85,
                        source="osv_structured",
                        raw_evidence=func,
                    ))

        return sinks

    # ------------------------------------------------------------------
    # LLM-based extraction
    # ------------------------------------------------------------------

    def _extract_sinks_via_llm(
        self,
        vuln_id: str,
        package_name: str,
        ecosystem: str,
        cwe: str,
        summary: str,
        details: str,
        aliases: List[str],
    ) -> List[VulnSink]:
        """Use LLM to extract vulnerable sinks from advisory text."""
        if not self.api_key:
            logger.warning("  [LLM] No OpenRouter API key — skipping LLM extraction")
            return []

        if not summary and not details:
            logger.warning(f"  [LLM] No advisory text for {vuln_id} — skipping")
            return []

        # Build prompt
        user_prompt = self._build_extraction_prompt(
            vuln_id=vuln_id,
            package_name=package_name,
            ecosystem=ecosystem,
            cwe=cwe,
            summary=summary,
            details=details[:3000],  # Truncate to avoid token limits
            aliases=aliases,
        )

        try:
            response = self._call_llm(user_prompt)
            sinks = self._parse_llm_response(response, vuln_id, package_name)
            return sinks
        except Exception as e:
            logger.error(f"  [LLM] Extraction failed for {vuln_id}: {e}")
            return []

    def _call_llm(self, user_prompt: str) -> str:
        """Call OpenRouter API and return the assistant's response text."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.llm_model,
            "temperature": self.llm_temperature,
            "max_tokens": self.llm_max_tokens,
            "messages": [
                {"role": "system", "content": self._prompt_template},
                {"role": "user", "content": user_prompt},
            ],
        }

        def _do_llm_post() -> requests.Response:
            r = requests.post(
                agent_config.OPENROUTER_BASE_URL,
                headers=headers,
                json=payload,
                timeout=60,
            )
            r.raise_for_status()
            return r

        resp = self._llm_limiter.call_with_retry(
            _do_llm_post,
            max_retries=agent_config.RATE_LIMIT_MAX_RETRIES,
        )
        data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            return ""
        return choices[0].get("message", {}).get("content", "")

    def _parse_llm_response(
        self,
        response_text: str,
        vuln_id: str,
        package_name: str,
    ) -> List[VulnSink]:
        """Parse LLM JSON response into VulnSink objects."""
        sinks: List[VulnSink] = []

        # Extract JSON from response (may be wrapped in ```json ... ```)
        text = response_text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.warning(f"  [LLM] Failed to parse JSON response for {vuln_id}")
            return []

        # Check if the parsed result is a list of batch items, e.g. [{"vuln_id": ..., "sinks": [...]}]
        items = []
        if isinstance(parsed, list):
            for entry in parsed:
                # If the list contains objects that have "sinks" array, it's a batch format
                if isinstance(entry, dict) and "sinks" in entry:
                    entry_sinks = entry.get("sinks", [])
                    for s in entry_sinks:
                        if isinstance(s, dict):
                            # Incorporate parent package/ecosystem into sink if missing
                            if "package_name" not in s and "package" in entry:
                                s["package_name"] = entry["package"]
                            if "ecosystem" not in s and "ecosystem" in entry:
                                s["ecosystem"] = entry["ecosystem"]
                            items.append(s)
                elif isinstance(entry, dict):
                    # Otherwise it may be a direct list of sinks
                    items.append(entry)
        elif isinstance(parsed, dict):
            # Expect {"sinks": [...]}
            items = parsed.get("sinks", [])

        for item in items:
            if not isinstance(item, dict):
                continue
            sinks.append(VulnSink(
                vuln_id=vuln_id,
                package_name=item.get("package_name", package_name),
                ecosystem=item.get("ecosystem", ""),
                function_name=item.get("function_name"),
                class_name=item.get("class_name"),
                call_pattern=item.get("call_pattern"),
                sink_type=item.get("sink_type", "function_call"),
                vuln_type=item.get("vuln_type", item.get("vulnerability_type", "")),
                confidence=min(float(item.get("confidence", 0.5)), 1.0),
                source="llm_extraction",
                raw_evidence=item.get("note", item.get("evidence", "")),
            ))

        return sinks

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    def _build_extraction_prompt(
        self,
        vuln_id: str,
        package_name: str,
        ecosystem: str,
        cwe: str,
        summary: str,
        details: str,
        aliases: List[str],
    ) -> str:
        parts = [
            "Extract sinks for exactly ONE vulnerability.",
            f'Use this exact identity in the single top-level array item: "vuln_id": "{vuln_id}", "package": "{package_name}", "ecosystem": "{ecosystem}".',
        ]
        if ecosystem:
            parts.append(f"Ecosystem: {ecosystem}")
        if cwe:
            parts.append(f"CWE: {cwe}")
        if aliases:
            parts.append(f"Aliases: {', '.join(aliases[:5])}")
        if summary:
            parts.append(f"\n--- Summary ---\n{summary}")
        if details:
            parts.append(f"\n--- Details ---\n{details}")

        parts.append(
            "\n--- Output constraints ---\n"
            "Return ONLY a JSON array with exactly one element for this vulnerability.\n"
            "- Return sink entries ONLY for high-precision callable sinks explicitly grounded in the advisory text.\n"
            '- If no safe callable is identified, return: '
            f'[{{"vuln_id":"{vuln_id}","package":"{package_name}","ecosystem":"{ecosystem}","sinks":[]}}]\n'
            "- Do NOT return import-only entries.\n"
            "- Do NOT return endpoint strings, wildcard patterns, or free-text descriptions.\n"
            "- Do NOT invent function names from framework knowledge or package internals.\n"
            "- Use at most one sink entry per callable name.\n"
            "- Generic names like request, fetch, get, parse, test, load, RegExp, URL, or Error are allowed only if the advisory explicitly ties them to the vulnerable package.\n"
            "- Allowed call shapes only: function call, method call, or constructor."
        )

        return "\n".join(parts)

    def _load_prompt_template(self) -> str:
        """Load system prompt from file, or use built-in default."""
        prompt_file = Path(__file__).parent / "prompts" / "vuln_sink_extraction.md"
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        return _DEFAULT_SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_function_name(qualified_name: str) -> str:
        """Extract bare function name from qualified path like 'pkg.mod.func'."""
        if not qualified_name:
            return ""
        # Handle Go-style: pkg.Func, JS-style: module.exports.func
        parts = qualified_name.replace("::", ".").split(".")
        return parts[-1] if parts else qualified_name

    @staticmethod
    def _extract_module_path(qualified_name: str) -> str:
        """Extract module/file path if present."""
        if not qualified_name:
            return ""
        if "/" in qualified_name:
            # Looks like a path: "src/minimatch.js:braceExpand"
            parts = qualified_name.split(":")
            return parts[0] if len(parts) > 1 else ""
        return ""

    @staticmethod
    def _deduplicate_sinks(sinks: List[VulnSink]) -> List[VulnSink]:
        """Keep highest-confidence sink per function_name."""
        seen: Dict[str, VulnSink] = {}
        for s in sinks:
            key = f"{s.package_name}::{s.function_name or s.class_name or s.sink_description}"
            if key not in seen or s.confidence > seen[key].confidence:
                seen[key] = s
        return list(seen.values())

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_results(
        self,
        results: List[VulnIntelResult],
        output_dir: Optional[Path] = None,
        project_name: str = "unknown",
    ) -> Path:
        """Save results to JSON file."""
        out_dir = output_dir or agent_config.AGENT_OUTPUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        safe_name = project_name.replace("/", "_").replace("\\", "_")
        out_file = out_dir / f"{safe_name}_vuln_sinks.json"

        data = {
            "project": project_name,
            "total_vulns": len(results),
            "total_sinks": sum(len(r.sinks) for r in results),
            "results": [r.to_dict() for r in results],
        }

        out_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info(f"[VulnIntel] Results saved to {out_file}")
        return out_file


# ---------------------------------------------------------------------------
# Default system prompt (used when prompts/vuln_sink_extraction.md not found)
# ---------------------------------------------------------------------------

_DEFAULT_SYSTEM_PROMPT = """You are a security researcher extracting vulnerable sink data from CVE advisories for Semgrep static analysis rules.

Respond ONLY with valid JSON in this exact format:
```json
{
  "sinks": [
    {
      "function_name": "braceExpand",
      "class_name": null,
      "call_pattern": "braceExpand(...)",
      "sink_type": "function_call",
      "vulnerability_type": "ReDoS",
      "confidence": 0.9,
      "note": "Advisory explicitly names braceExpand as the vulnerable function."
    }
  ]
}
```

CRITICAL RULES:
- function_name MUST only be filled if the function name appears literally in the advisory text.
  Do NOT infer function names from your knowledge of the package internals.
- confidence: 0.9 = function explicitly named in advisory text; 0.7 = API usage pattern described but no function name; 0.5 = package-level only; 0.3 = CWE heuristic only
- call_pattern must be a valid Semgrep pattern (e.g. "func(...)", "$OBJ.method(...)", "new Class(...)") — NOT a free-text description.
- If no specific function is identifiable from the advisory text, set function_name to null.
- Return "sinks": [] if the advisory only describes behavioral or architectural impact with no callable entrypoint. Do NOT invent a sink just to avoid an empty result.
"""
