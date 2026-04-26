from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.llm_service import (  # noqa: E402
    _anthropic_payload_from_messages,
    compute_total_input_tokens,
    extract_claude_usage_metrics,
)
import backend.config as config  # noqa: E402


class ClaudePromptCachingTests(unittest.TestCase):
    def test_anthropic_payload_includes_cache_control_when_enabled(self) -> None:
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "stable rules"},
            {"role": "user", "content": "dynamic payload"},
        ]
        with (
            patch.object(config, "CLAUDE_PROMPT_CACHING_ENABLED", True),
            patch.object(config, "CLAUDE_PROMPT_CACHE_TTL", "1h"),
            patch.object(config, "LLM_PROVIDER", "anthropic"),
        ):
            payload = _anthropic_payload_from_messages(
                messages,
                request_options={
                    "enable_prompt_caching": True,
                    "stable_prefix_text": "A" * 2000,
                    "purpose": "test_report",
                },
            )

        self.assertIn("cache_control", payload)
        self.assertEqual(payload["cache_control"], {"type": "ephemeral", "ttl": "1h"})

    def test_anthropic_payload_skips_cache_control_for_short_prefix(self) -> None:
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "stable rules"},
        ]
        with (
            patch.object(config, "CLAUDE_PROMPT_CACHING_ENABLED", True),
            patch.object(config, "CLAUDE_PROMPT_CACHE_TTL", "5m"),
            patch.object(config, "LLM_PROVIDER", "anthropic"),
        ):
            payload = _anthropic_payload_from_messages(
                messages,
                request_options={
                    "enable_prompt_caching": True,
                    "stable_prefix_text": "short prefix",
                    "purpose": "test_report",
                },
            )

        self.assertNotIn("cache_control", payload)

    def test_usage_helper_computes_total_input_tokens(self) -> None:
        usage = extract_claude_usage_metrics(
            {
                "usage": {
                    "cache_creation_input_tokens": 100,
                    "cache_read_input_tokens": 250,
                    "input_tokens": 40,
                    "output_tokens": 60,
                }
            }
        )
        self.assertEqual(compute_total_input_tokens(usage), 390)
        self.assertEqual(usage["output_tokens"], 60)


if __name__ == "__main__":
    unittest.main()
