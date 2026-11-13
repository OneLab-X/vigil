"""Gemini adapter tests against a mocked generateContent endpoint (no network, no real model)."""
import json
from datetime import date

import httpx
import pytest

from vigil_agents.agent import Limits, RunRequest, run_agent
from vigil_agents.pricing import cost_usd
from vigil_agents.providers import GeminiProvider, ProviderError, make_provider

from test_agent import GOOD, make_broker


def gemini(responses: list, seen: list) -> GeminiProvider:
    it = iter(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        r = next(it)
        return r if isinstance(r, httpx.Response) else httpx.Response(200, json=r)

    p = GeminiProvider("gemini-4-argon", http=httpx.AsyncClient(base_url="https://g", transport=httpx.MockTransport(handler)))
    p.max_retries = 1
    return p


def turn(parts, finish="STOP", usage=(1000, 200, 300)):
    return {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}],
            "usageMetadata": {"promptTokenCount": usage[0], "candidatesTokenCount": usage[1], "thoughtsTokenCount": usage[2]}}


def req():
    return RunRequest("r1", "investigation_analyst", "CASE-0001", "investigate", "tok", "http://broker",
                      ["get_case_context", "search_events"], "gemini", "gemini-4-argon", "v", Limits())


async def test_tool_round_trip_preserves_thought_signature_and_call_id():
    seen: list = []
    p = gemini([
        turn([{"functionCall": {"id": "fc-1", "name": "get_case_context", "args": {}}, "thoughtSignature": "SIG-A"}]),
        turn([{"functionCall": {"id": "fc-2", "name": "submit_result", "args": GOOD}, "thoughtSignature": "SIG-B"}]),
    ], seen)
    out = await run_agent(req(), p, make_broker([]))
    assert out.status == "succeeded", out.error
    second = seen[1]["contents"]
    assert second[1]["parts"][0]["thoughtSignature"] == "SIG-A"  # model turn sent back unchanged
    fr = second[2]["parts"][0]["functionResponse"]
    assert fr["id"] == "fc-1" and fr["name"] == "get_case_context"
    assert fr["response"]["content"].startswith("<untrusted_log_data")
    # Full JSON Schema (with $defs) goes through parametersJsonSchema; no temperature is sent.
    decls = seen[0]["tools"][0]["functionDeclarations"]
    assert all("parametersJsonSchema" in d for d in decls)
    assert "temperature" not in seen[0]["generationConfig"]
    # Thinking tokens are billed as output.
    assert out.output_tokens == 2 * 500
    assert out.cost_usd == pytest.approx(cost_usd("gemini-4-argon", 2000, 1000))
    assert out.cost_usd > 0


async def test_safety_block_fails_run():
    p = gemini([turn([], finish="SAFETY")], [])
    out = await run_agent(req(), p, make_broker([]))
    assert out.status == "failed" and "SAFETY" in (out.error or "")


async def test_prompt_block_fails_run():
    p = gemini([{"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}}], [])
    out = await run_agent(req(), p, make_broker([]))
    assert out.status == "failed" and "PROHIBITED_CONTENT" in (out.error or "")


async def test_retries_on_429_then_succeeds():
    p = gemini([httpx.Response(429, headers={"retry-after": "0"}, text="rate"),
                turn([{"functionCall": {"name": "submit_result", "args": GOOD}}])], [])
    out = await run_agent(req(), p, make_broker([]))
    assert out.status == "succeeded", out.error


async def test_cost_budget_enforced():
    p = gemini([turn([{"functionCall": {"name": "get_case_context", "args": {}}}], usage=(400_000, 10_000, 0))], [])
    r = req()
    r.limits = Limits(cost_budget_usd=0.5, token_budget=2_000_000)
    out = await run_agent(r, p, make_broker([]))
    assert out.status == "failed" and "cost budget" in (out.error or "")


def test_unpriced_model_is_refused():
    with pytest.raises(ProviderError, match="no price configured"):
        make_provider("gemini", "gemini-unknown-model")


def test_price_changes_on_effective_date():
    assert cost_usd("gemini-4-argon", 1_000_000, 0, today=date(2026, 11, 30)) == 2.0
    assert cost_usd("gemini-4-argon", 1_000_000, 0, today=date(2026, 12, 1)) == 4.0
