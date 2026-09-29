"""Small, content-free usage measurements for Suricata investigations."""

from __future__ import annotations

import json
from typing import Any


# Offline approximation only. API response.usage remains the authoritative count.
ESTIMATED_CHARS_PER_TOKEN = 4
GPT6_SOL_SHORT_CONTEXT_LIMIT = 272_000
GPT6_SOL_RATES_USD_PER_MILLION = {
    "short": {"input": 2.0, "cached": 0.2, "cache_write": 2.5, "output": 10.0},
    "long": {"input": 4.0, "cached": 0.4, "cache_write": 5.0, "output": 15.0},
}


def json_text(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def estimated_tokens(value: Any) -> int:
    """Estimate serialized text tokens without an API call or tokenizer dependency."""
    content = value if isinstance(value, str) else json_text(value)
    return (len(content) + ESTIMATED_CHARS_PER_TOKEN - 1) // ESTIMATED_CHARS_PER_TOKEN


def utf8_bytes(value: Any) -> int:
    content = value if isinstance(value, str) else json_text(value)
    return len(content.encode("utf-8"))


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def response_usage(payload: dict[str, Any]) -> dict[str, int] | None:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    input_details = usage.get("input_tokens_details") or {}
    output_details = usage.get("output_tokens_details") or {}
    if not isinstance(input_details, dict):
        input_details = {}
    if not isinstance(output_details, dict):
        output_details = {}
    return {
        "input_tokens": _nonnegative_int(usage.get("input_tokens")),
        "cached_input_tokens": _nonnegative_int(input_details.get("cached_tokens")),
        "cache_write_tokens": _nonnegative_int(input_details.get("cache_write_tokens")),
        "output_tokens": _nonnegative_int(usage.get("output_tokens")),
        "reasoning_tokens": _nonnegative_int(output_details.get("reasoning_tokens")),
    }


def estimated_cost_usd(model: str, usage: dict[str, int]) -> float | None:
    """Estimate standard GPT-6 Sol text cost; unknown models are not guessed."""
    if model != "gpt-6-sol":
        return None
    input_tokens = usage["input_tokens"]
    cached = min(input_tokens, usage["cached_input_tokens"])
    cache_write = min(input_tokens - cached, usage["cache_write_tokens"])
    ordinary = input_tokens - cached - cache_write
    rates = GPT6_SOL_RATES_USD_PER_MILLION[
        "long" if input_tokens > GPT6_SOL_SHORT_CONTEXT_LIMIT else "short"
    ]
    return round((ordinary * rates["input"] + cached * rates["cached"]
                  + cache_write * rates["cache_write"]
                  + usage["output_tokens"] * rates["output"]) / 1_000_000, 8)


class InvestigationMetrics:
    def __init__(self, model: str):
        self.model = model
        self.requests: list[dict[str, Any]] = []
        self.tool_results: list[dict[str, Any]] = []

    def record_request(self, body: dict[str, Any], payload: dict[str, Any]) -> None:
        usage = response_usage(payload)
        self.requests.append({
            "request_bytes": utf8_bytes(body),
            "replayed_context_estimated_tokens": estimated_tokens(body.get("input", [])),
            "usage": usage,
            "estimated_cost_usd": estimated_cost_usd(self.model, usage) if usage else None,
        })

    def record_tool(self, name: str, full_result: Any, model_result: Any) -> None:
        self.tool_results.append({
            "name": name,
            "full_result_bytes": utf8_bytes(full_result),
            "tool_result_bytes": utf8_bytes(model_result),
            "estimated_tool_result_tokens": estimated_tokens(model_result),
        })

    def snapshot(self, retained_context: Any) -> dict[str, Any]:
        reported = [item for item in self.requests if item["usage"] is not None]
        usage_fields = ("input_tokens", "cached_input_tokens", "cache_write_tokens", "output_tokens", "reasoning_tokens")
        totals = {field: sum(item["usage"][field] for item in reported) for field in usage_fields}
        totals["total_tokens"] = totals["input_tokens"] + totals["output_tokens"]
        costs = [item["estimated_cost_usd"] for item in reported]
        full_tool_bytes = sum(item["full_result_bytes"] for item in self.tool_results)
        model_tool_bytes = sum(item["tool_result_bytes"] for item in self.tool_results)
        return {
            "model": self.model,
            "api_calls": len(self.requests),
            "api_calls_with_usage": len(reported),
            "usage_complete": bool(self.requests) and len(reported) == len(self.requests),
            **totals,
            "cached_input_ratio": round(totals["cached_input_tokens"] / totals["input_tokens"], 4) if totals["input_tokens"] else None,
            "tool_result_bytes": model_tool_bytes,
            "full_local_tool_result_bytes": full_tool_bytes,
            "tool_payload_reduction_bytes": max(0, full_tool_bytes - model_tool_bytes),
            "estimated_tool_result_tokens": sum(item["estimated_tool_result_tokens"] for item in self.tool_results),
            "replayed_context_estimated_tokens": sum(item["replayed_context_estimated_tokens"] for item in self.requests),
            "retained_context_estimated_tokens": estimated_tokens(retained_context),
            "estimated_cost_usd": round(sum(costs), 8) if len(reported) == len(self.requests) and reported and all(cost is not None for cost in costs) else None,
            "cost_note": "Estimated standard GPT-6 Sol text rates as documented 2026-09-28; excludes taxes/other tiers. Unknown models have no cost estimate.",
            "token_estimate_note": "Local text estimates use 4 characters per token; API usage counters are authoritative.",
            "requests": list(self.requests),
            "tool_results": list(self.tool_results),
        }
