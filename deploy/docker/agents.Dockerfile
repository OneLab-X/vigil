# AI agent worker. Holds no DB or cloud credentials; reaches only the model provider and the tool broker.
FROM ghcr.io/astral-sh/uv:0.13.5 AS uv
FROM python:3.13.18-slim-bookworm AS runtime
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/agents/pyproject.toml services/agents/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY services/agents/vigil_agents vigil_agents
RUN uv sync --frozen --no-dev \
 && useradd --system --uid 10001 vigil
USER vigil
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/healthz',timeout=4).status==200 else 1)"
CMD ["uvicorn", "vigil_agents.app:app", "--host", "0.0.0.0", "--port", "8090"]
