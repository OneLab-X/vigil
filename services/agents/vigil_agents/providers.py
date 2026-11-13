"""Model-provider abstraction.

Each provider keeps its own native transcript (so provider-specific blocks such as Claude thinking
blocks are passed back unchanged) and exposes one neutral step interface to the agent loop.
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class StepResult:
    text: str
    tool_calls: list[ToolCall]
    input_tokens: int
    output_tokens: int
    stop: str  # end_turn | tool_use | max_tokens | refusal | error
    served_by: str | None = None


@dataclass
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


class ProviderError(RuntimeError):
    pass


@dataclass
class ModelConfig:
    """Per-run model settings from the control plane (customer-configured providers). api_key is held in memory only."""
    endpoint: str | None = None
    api_key: str | None = field(default=None, repr=False)
    timeout_seconds: float = 120
    price: tuple[float, float] | None = None  # USD per 1M tokens (input, output)


_BLOCKED_NAMES = {"metadata.google.internal", "metadata", "metadata.azure.com", "instance-data", "instance-data.ec2.internal"}


def assert_endpoint_allowed(url: str) -> str:
    """SSRF guard, re-checked here at call time: private/LAN hosts are fine (customer-hosted models), cloud metadata
    and link-local addresses never are. Resolves the host so a DNS name can't point at a blocked address."""
    import ipaddress
    import socket
    from urllib.parse import urlsplit

    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ProviderError("model endpoint must be an http(s) URL")
    if u.username or u.password:
        raise ProviderError("credentials in the endpoint URL are not allowed")
    host = u.hostname.lower()
    if host in _BLOCKED_NAMES:
        raise ProviderError("cloud metadata endpoints are not allowed")
    try:
        infos = socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except OSError as e:
        raise ProviderError(f"cannot resolve model endpoint host: {e.strerror or e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        mapped = getattr(ip, "ipv4_mapped", None)
        ip = mapped or ip
        if ip.is_link_local or ip.is_unspecified or str(ip) in ("100.100.100.200", "fd00:ec2::254"):
            raise ProviderError("model endpoint resolves to a link-local / metadata address")
    return url.rstrip("/")


class Provider(Protocol):
    name: str
    model: str

    def start(self, system: str, tools: list[dict[str, Any]], user_text: str) -> None: ...
    async def step(self) -> StepResult: ...
    def add_tool_results(self, results: list[ToolResult]) -> None: ...
    def add_user_text(self, text: str) -> None: ...


# ---------------------------------------------------------------- Anthropic (official SDK)
class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, effort: str = "high", cfg: ModelConfig | None = None):
        from anthropic import AsyncAnthropic  # imported lazily so other providers don't need it

        cfg = cfg or ModelConfig()
        self.model = model
        self.effort = effort
        self.price = cfg.price
        kw: dict[str, Any] = {"timeout": cfg.timeout_seconds}
        if cfg.api_key:
            kw["api_key"] = cfg.api_key
        if cfg.endpoint:
            kw["base_url"] = assert_endpoint_allowed(cfg.endpoint)
        self.client = AsyncAnthropic(**kw)  # without an explicit key: ANTHROPIC_API_KEY / auth token / profile from the environment
        self.messages: list[dict[str, Any]] = []
        self.system = ""
        self.tools: list[dict[str, Any]] = []

    def start(self, system, tools, user_text):
        self.system = system
        self.tools = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]
        self.messages = [{"role": "user", "content": user_text}]

    async def step(self) -> StepResult:
        import anthropic

        try:
            resp = await self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=[{"type": "text", "text": self.system, "cache_control": {"type": "ephemeral"}}],
                **({"tools": self.tools} if self.tools else {}),
                messages=self.messages,
                output_config={"effort": self.effort},
                # Server-side refusal fallback: routes a declined request to an appropriate model.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.RateLimitError as e:
            raise ProviderError(f"rate limited: {e}") from e
        except anthropic.APIStatusError as e:
            raise ProviderError(f"anthropic HTTP {e.status_code}: {str(e)[:300]}") from e
        except anthropic.APIConnectionError as e:
            raise ProviderError(f"anthropic connection error: {e}") from e

        # Append the full content unchanged (thinking / fallback blocks must be preserved).
        self.messages.append({"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in resp.content]})
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in resp.content if b.type == "tool_use"]
        stop = resp.stop_reason or "end_turn"
        return StepResult(text, calls, resp.usage.input_tokens, resp.usage.output_tokens, stop, served_by=resp.model)

    def add_tool_results(self, results):
        # All results for one assistant turn go back in a single user message.
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": r.call_id, "content": r.content, "is_error": r.is_error} for r in results
        ]})

    def add_user_text(self, text):
        self.messages.append({"role": "user", "content": text})


# ---------------------------------------------------------------- OpenAI (Chat Completions, raw HTTP)
class OpenAIProvider:
    """OpenAI Chat Completions. With a custom endpoint it serves any OpenAI-compatible server
    (Ollama `/v1`, vLLM, LM Studio, LiteLLM, Azure-style gateways)."""

    name = "openai"

    def __init__(self, model: str, cfg: ModelConfig | None = None, compatible: bool = False, http: httpx.AsyncClient | None = None):
        cfg = cfg or ModelConfig()
        key = cfg.api_key or (None if compatible else os.environ.get("OPENAI_API_KEY"))
        if not key and not compatible and http is None:
            raise ProviderError("OPENAI_API_KEY not configured")
        if compatible and not cfg.endpoint and http is None:
            raise ProviderError("openai_compatible provider needs an endpoint")
        base = assert_endpoint_allowed(cfg.endpoint) if cfg.endpoint and http is None else (cfg.endpoint or "https://api.openai.com/v1")
        self.name = "openai_compatible" if compatible else "openai"
        self.model = model
        self.price = cfg.price
        headers = {"authorization": f"Bearer {key}"} if key else {}
        self.http = http or httpx.AsyncClient(base_url=base, headers=headers, timeout=cfg.timeout_seconds, follow_redirects=False)
        self.messages: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []

    def start(self, system, tools, user_text):
        self.tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}} for t in tools]
        self.messages = [{"role": "system", "content": system}, {"role": "user", "content": user_text}]

    async def step(self):
        body: dict[str, Any] = {"model": self.model, "messages": self.messages}
        if self.tools:
            body["tools"] = self.tools
        try:
            r = await self.http.post("/chat/completions", json=body)
        except httpx.HTTPError as e:
            raise ProviderError(f"{self.name} connection error: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise ProviderError(f"{self.name} HTTP {r.status_code}: {r.text[:300]}")
        d = r.json()
        choice = (d.get("choices") or [{}])[0]
        msg = choice.get("message") or {"role": "assistant", "content": ""}
        self.messages.append(msg)
        calls = []
        for c in msg.get("tool_calls") or []:
            raw = c["function"].get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                args = {"_invalid_json": raw[:2000]}  # fails contract validation -> model is asked to repair
            calls.append(ToolCall(c.get("id") or f"call_{len(self.messages)}", c["function"]["name"], args if isinstance(args, dict) else {}))
        u = d.get("usage") or {}
        finish = choice.get("finish_reason")
        stop = "tool_use" if calls else ("max_tokens" if finish == "length" else ("refusal" if finish == "content_filter" else "end_turn"))
        return StepResult(msg.get("content") or "", calls, u.get("prompt_tokens", 0), u.get("completion_tokens", 0), stop, self.model)

    def add_tool_results(self, results):
        for r in results:
            self.messages.append({"role": "tool", "tool_call_id": r.call_id, "content": r.content})

    def add_user_text(self, text):
        self.messages.append({"role": "user", "content": text})


# ---------------------------------------------------------------- Gemini (generateContent, raw HTTP)
# Finish reasons that mean the response was withheld or unusable; the run fails with the reason.
_GEMINI_BLOCKED = {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY", "LANGUAGE", "OTHER"}


class GeminiProvider:
    name = "gemini"
    max_retries = 3

    def __init__(self, model: str, http: httpx.AsyncClient | None = None, cfg: ModelConfig | None = None):
        cfg = cfg or ModelConfig(timeout_seconds=180)
        key = cfg.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key and http is None:
            raise ProviderError("GEMINI_API_KEY not configured")
        self.model = model
        self.price = cfg.price
        base = assert_endpoint_allowed(cfg.endpoint) if cfg.endpoint else "https://generativelanguage.googleapis.com/v1beta"
        self.http = http or httpx.AsyncClient(base_url=base, headers={"x-goog-api-key": key or ""}, timeout=cfg.timeout_seconds, follow_redirects=False)
        self.thinking_level = os.environ.get("VIGIL_GEMINI_THINKING_LEVEL")  # low | medium | high; unset = model default
        self.contents: list[dict[str, Any]] = []
        self.system = ""
        self.tools: list[dict[str, Any]] = []
        self._n = 0
        self._ids: dict[str, tuple[str, str | None]] = {}  # our call id -> (function name, gemini call id)

    def start(self, system, tools, user_text):
        self.system = system
        # parametersJsonSchema accepts full JSON Schema ($defs/$ref from Pydantic), unlike the OpenAPI-subset `parameters`.
        self.tools = [{"functionDeclarations": [{"name": t["name"], "description": t["description"], "parametersJsonSchema": t["parameters"]} for t in tools]}]
        self.contents = [{"role": "user", "parts": [{"text": user_text}]}]

    def _body(self) -> dict[str, Any]:
        gen: dict[str, Any] = {"maxOutputTokens": 16000}  # no temperature: ignored by current Gemini models
        if self.thinking_level:
            gen["thinkingConfig"] = {"thinkingLevel": self.thinking_level}
        body: dict[str, Any] = {"systemInstruction": {"parts": [{"text": self.system}]}, "contents": self.contents, "generationConfig": gen}
        if self.tools and self.tools[0]["functionDeclarations"]:
            body["tools"] = self.tools
            body["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
        return body

    async def _post(self) -> dict[str, Any]:
        for attempt in range(self.max_retries + 1):
            try:
                r = await self.http.post(f"/models/{self.model}:generateContent", json=self._body())
            except httpx.HTTPError as e:
                if attempt == self.max_retries:
                    raise ProviderError(f"gemini connection error: {type(e).__name__}") from e
                await asyncio.sleep(2 ** attempt)
                continue
            if r.status_code == 429 or r.status_code >= 500:
                if attempt == self.max_retries:
                    raise ProviderError(f"gemini HTTP {r.status_code} after {attempt + 1} attempts: {r.text[:300]}")
                ra = r.headers.get("retry-after")
                await asyncio.sleep(min(float(ra), 30.0) if ra and ra.replace(".", "", 1).isdigit() else 2 ** attempt)
                continue
            if r.status_code >= 400:
                raise ProviderError(f"gemini HTTP {r.status_code}: {r.text[:300]}")
            return r.json()
        raise ProviderError("gemini: retries exhausted")  # unreachable

    async def step(self):
        d = await self._post()
        block = (d.get("promptFeedback") or {}).get("blockReason")
        if block:
            raise ProviderError(f"gemini blocked the prompt: {block}")
        cands = d.get("candidates") or []
        if not cands:
            raise ProviderError("gemini returned no candidates")
        cand = cands[0]
        finish = cand.get("finishReason") or "STOP"
        if finish in _GEMINI_BLOCKED:
            raise ProviderError(f"gemini withheld the response: finishReason={finish}")
        if finish == "MALFORMED_FUNCTION_CALL":
            # Nothing usable to keep in the transcript; ask the model to retry the call.
            self.contents.append({"role": "user", "parts": [{"text": "Your last function call was malformed. Call the tool again with valid JSON arguments."}]})
            u = d.get("usageMetadata", {})
            return StepResult("", [], u.get("promptTokenCount", 0), u.get("candidatesTokenCount", 0) + u.get("thoughtsTokenCount", 0), "end_turn", self.model)
        content = cand.get("content") or {"role": "model", "parts": []}
        content.setdefault("role", "model")
        # Append the model turn unchanged: parts may carry thoughtSignature, which must be sent back as received.
        self.contents.append(content)
        calls, text = [], ""
        for p in content.get("parts", []):
            if "functionCall" in p:
                fc = p["functionCall"]
                self._n += 1
                cid = f"{fc['name']}#{self._n}"
                self._ids[cid] = (fc["name"], fc.get("id"))
                calls.append(ToolCall(cid, fc["name"], fc.get("args") or {}))
            elif "text" in p and not p.get("thought"):
                text += p["text"]
        u = d.get("usageMetadata", {})
        stop = "tool_use" if calls else ("max_tokens" if finish == "MAX_TOKENS" else "end_turn")
        return StepResult(text, calls, u.get("promptTokenCount", 0), u.get("candidatesTokenCount", 0) + u.get("thoughtsTokenCount", 0), stop, self.model)

    def add_tool_results(self, results):
        parts = []
        for r in results:
            name, gid = self._ids.get(r.call_id, (r.call_id.split("#")[0], None))
            fr: dict[str, Any] = {"name": name, "response": {"content": r.content, "is_error": r.is_error}}
            if gid:
                fr["id"] = gid
            parts.append({"functionResponse": fr})
        self.contents.append({"role": "user", "parts": parts})

    def add_user_text(self, text):
        self.contents.append({"role": "user", "parts": [{"text": text}]})


# ---------------------------------------------------------------- Scripted (tests / evaluation only)
@dataclass
class ScriptedProvider:
    """Deterministic provider that replays a scripted list of turns. Refused unless explicitly enabled."""

    script: list[dict[str, Any]]
    name: str = "scripted"
    model: str = "test-script"
    seen: list[Any] = field(default_factory=list)
    _i: int = 0

    def __post_init__(self):
        if os.environ.get("VIGIL_ALLOW_SCRIPTED_PROVIDER") != "1":
            raise ProviderError("scripted provider is disabled (test/eval only)")

    def start(self, system, tools, user_text):
        self.seen.append({"system": system, "tools": [t["name"] for t in tools], "user": user_text})

    async def step(self):
        turn = self.script[self._i] if self._i < len(self.script) else {"text": "done"}
        self._i += 1
        if callable(turn):
            turn = turn(self.seen)
        calls = [ToolCall(f"c{self._i}_{k}", c["name"], c.get("args", {})) for k, c in enumerate(turn.get("calls", []))]
        return StepResult(turn.get("text", ""), calls, 100, 50, "tool_use" if calls else "end_turn", self.model)

    def add_tool_results(self, results):
        self.seen.append({"tool_results": [r.__dict__ for r in results]})

    def add_user_text(self, text):
        self.seen.append({"user": text})


def make_provider(provider: str, model: str, script: list[dict[str, Any]] | None = None, cfg: ModelConfig | None = None) -> Provider:
    from .pricing import require_price

    if not (cfg and cfg.price is not None):
        try:
            require_price(model)
        except ValueError as e:
            raise ProviderError(str(e)) from e
    if provider == "anthropic":
        return AnthropicProvider(model, cfg=cfg)
    if provider == "openai":
        return OpenAIProvider(model, cfg=cfg)
    if provider == "openai_compatible":
        return OpenAIProvider(model, cfg=cfg, compatible=True)
    if provider == "gemini":
        return GeminiProvider(model, cfg=cfg)
    if provider == "scripted":
        return ScriptedProvider(script or [])
    raise ProviderError(f"unknown provider {provider}")
