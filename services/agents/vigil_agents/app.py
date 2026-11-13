"""FastAPI entrypoint. Accepts run dispatches from the control plane and executes them in the background."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .agent import Broker, Limits, RunOutcome, RunRequest, run_agent
from .providers import ModelConfig, ProviderError, make_provider

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("vigil.agents")
app = FastAPI(title="Vigil Agent Worker", version="0.1.0")
_tasks: set[asyncio.Task] = set()
MAX_CONCURRENT = int(os.environ.get("VIGIL_AGENT_CONCURRENCY", "4"))
_sem = asyncio.Semaphore(MAX_CONCURRENT)


class LimitsIn(BaseModel):
    max_steps: int = Field(ge=1, le=40)
    timeout_seconds: int = Field(ge=10, le=1800)
    token_budget: int = Field(ge=1000, le=2_000_000)
    cost_budget_usd: float = Field(gt=0, le=50)


class ModelIn(BaseModel):
    provider: str = Field(pattern="^(anthropic|openai|gemini|openai_compatible|scripted)$")
    name: str = Field(min_length=1, max_length=128)
    endpoint: str | None = Field(default=None, max_length=500)
    api_key: str | None = Field(default=None, max_length=4000, repr=False)
    timeout_seconds: float | None = Field(default=None, ge=5, le=1800)
    price_input_per_mtok: float | None = Field(default=None, ge=0, le=1000)
    price_output_per_mtok: float | None = Field(default=None, ge=0, le=1000)

    def config(self) -> ModelConfig:
        price = (self.price_input_per_mtok, self.price_output_per_mtok) if self.price_input_per_mtok is not None and self.price_output_per_mtok is not None else None
        return ModelConfig(endpoint=self.endpoint, api_key=self.api_key, timeout_seconds=self.timeout_seconds or 120, price=price)


class RunIn(BaseModel):
    run_id: str
    role: str = Field(pattern="^(detection_analyst|investigation_analyst)$")
    case_id: str
    task: str = Field(max_length=4000)
    run_token: str
    broker_url: str
    tools: list[str]
    model: ModelIn
    prompt_version: str
    limits: LimitsIn


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Never echo request input back: run requests can carry a model API key.
    return JSONResponse(status_code=422, content={"detail": [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]})


def _check_internal(auth: str | None) -> None:
    expected = os.environ.get("VIGIL_INTERNAL_TOKEN", "dev-internal-token-change-me")
    if not auth or not hmac.compare_digest(auth, f"Bearer {expected}"):
        raise HTTPException(401, "unauthorized")


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"ok": True, "active_runs": len(_tasks), "providers": {
        "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")),
        "openai": bool(os.environ.get("OPENAI_API_KEY")),
        "gemini": bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")),
    }}


async def _execute(body: RunIn) -> None:
    cfg = body.model.config()
    req = RunRequest(run_id=body.run_id, role=body.role, case_id=body.case_id, task=body.task, run_token=body.run_token,
                     broker_url=body.broker_url, tools=body.tools, model_provider=body.model.provider, model_name=body.model.name,
                     prompt_version=body.prompt_version, limits=Limits(**body.limits.model_dump()))
    broker = Broker(req.broker_url, req.run_token)
    async with _sem:
        try:
            provider = make_provider(req.model_provider, req.model_name, cfg=cfg)
            outcome = await run_agent(req, provider, broker)
        except ProviderError as e:
            outcome = RunOutcome(status="failed", error=f"provider unavailable: {e}")
        except Exception as e:  # e.g. SDK raises when no credentials are configured
            outcome = RunOutcome(status="failed", error=f"provider unavailable: {type(e).__name__}: {str(e)[:300]}")
        log.info(json.dumps({"msg": "run finished", "run_id": req.run_id, "role": req.role, "status": outcome.status, "steps": outcome.steps, "cost_usd": round(outcome.cost_usd, 4), "error": outcome.error}))
        await broker.submit(req.run_id, outcome, req.model_provider, req.model_name)


@app.post("/v1/runs", status_code=202)
async def start_run(body: RunIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_internal(authorization)
    t = asyncio.create_task(_execute(body))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return {"accepted": True, "run_id": body.run_id}


@app.post("/v1/providers/test")
async def test_provider(body: ModelIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Probe a provider config with one tiny request (a few tokens). Used by Settings → AI models → Test."""
    _check_internal(authorization)
    try:
        p = make_provider(body.provider, body.name, cfg=body.config())
        p.start("You are a connectivity check. Reply with the single word OK.", [], "ping")
        res = await asyncio.wait_for(p.step(), timeout=(body.timeout_seconds or 30) + 5)
        return {"ok": True, "detail": f"{body.provider}/{body.name} answered ({res.input_tokens} in / {res.output_tokens} out tokens)"}
    except ProviderError as e:
        return {"ok": False, "detail": str(e)[:400]}
    except asyncio.TimeoutError:
        return {"ok": False, "detail": "timed out"}
    except Exception as e:  # SDK/HTTP errors: class + message only
        return {"ok": False, "detail": f"{type(e).__name__}: {str(e)[:300]}"}
