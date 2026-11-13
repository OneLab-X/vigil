"""OpenAI-compatible / customer-hosted provider, SSRF guard, per-run price, key never echoed."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from vigil_agents.agent import Limits, RunRequest, run_agent
from vigil_agents.app import app
from vigil_agents.providers import ModelConfig, OpenAIProvider, ProviderError, assert_endpoint_allowed, make_provider

from test_agent import GOOD, make_broker


def compat(responses, seen, price=(0.0, 0.0)):
    it = iter(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=next(it))

    return OpenAIProvider("llama3.1:8b", cfg=ModelConfig(endpoint="http://ollama:11434/v1", price=price), compatible=True,
                          http=httpx.AsyncClient(base_url="http://ollama:11434/v1", transport=httpx.MockTransport(handler)))


def msg(calls=None, content="", usage=(500, 50)):
    m = {"role": "assistant", "content": content}
    if calls:
        m["tool_calls"] = [{"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": a}} for i, (n, a) in enumerate(calls)]
    return {"choices": [{"message": m, "finish_reason": "tool_calls" if calls else "stop"}], "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]}}


def req():
    return RunRequest("r1", "investigation_analyst", "CASE-0001", "investigate", "tok", "http://broker",
                      ["get_case_context"], "openai_compatible", "llama3.1:8b", "v", Limits())


async def test_local_model_run_with_invalid_json_repair_and_zero_price():
    seen: list = []
    p = compat([
        msg([("get_case_context", "{}")]),
        msg([("submit_result", "{not json")]),          # malformed arguments from a small local model
        msg([("submit_result", json.dumps(GOOD))]),
    ], seen)
    out = await run_agent(req(), p, make_broker([]))
    assert out.status == "succeeded", out.error
    assert out.cost_usd == 0.0  # customer-hosted, configured price 0
    assert seen[0]["model"] == "llama3.1:8b" and "tools" in seen[0]


async def test_configured_price_is_used_for_budget():
    p = compat([msg([("get_case_context", "{}")], usage=(1_000_000, 0))], [], price=(5.0, 5.0))
    r = req()
    r.limits = Limits(cost_budget_usd=1.0, token_budget=2_000_000)
    out = await run_agent(r, p, make_broker([]))
    assert out.status == "failed" and "cost budget" in (out.error or "")


@pytest.mark.parametrize("url", ["http://169.254.169.254/v1", "http://metadata.google.internal/v1", "http://[fe80::1]/v1", "ftp://x/v1", "http://u:p@10.0.0.5/v1"])
def test_ssrf_guard_blocks(url):
    with pytest.raises(ProviderError):
        assert_endpoint_allowed(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434/v1", "http://10.1.2.3:8000/v1", "https://api.openai.com/v1"])
def test_ssrf_guard_allows_private_and_public(url):
    assert assert_endpoint_allowed(url)


def test_unknown_model_allowed_only_with_configured_price():
    with pytest.raises(ProviderError, match="no price configured"):
        make_provider("openai_compatible", "mystery-model", cfg=ModelConfig(endpoint="http://127.0.0.1:1/v1"))
    p = make_provider("openai_compatible", "mystery-model", cfg=ModelConfig(endpoint="http://127.0.0.1:1/v1", price=(0.0, 0.0)))
    assert p.name == "openai_compatible"


def test_validation_error_never_echoes_api_key(monkeypatch):
    monkeypatch.setenv("VIGIL_INTERNAL_TOKEN", "t")
    c = TestClient(app)
    r = c.post("/v1/runs", headers={"authorization": "Bearer t"}, json={"model": {"provider": "gemini", "name": "x", "api_key": "SUPER-SECRET-KEY"}})
    assert r.status_code == 422
    assert "SUPER-SECRET-KEY" not in r.text
