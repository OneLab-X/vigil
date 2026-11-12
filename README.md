# Vigil

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/OneLab-X/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/OneLab-X/vigil/actions/workflows/ci.yml)
![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange)

**Open-source, self-hosted, AI-assisted security operations for your clouds.** Vigil reads your cloud and log-platform
audit data with read-only, keyless credentials, detects suspicious activity with deterministic rules, has AI agents
investigate each incident with evidence they can only reach through a governed tool broker, and leaves the final
decision to a human.

Cloud signals → ingestion → normalization → deterministic detection → correlation → AI investigation
→ evidence-backed verdict → **human decision** → organizational learning.

<!-- Screenshot: docs/images/overview.png (add before first public release) -->

## Features

- **Connectors** (read-only, least privilege, keyless where the cloud supports it): GCP Cloud Logging, AWS CloudTrail /
  CloudWatch Logs, Azure Activity Log / Entra ID / Defender for Cloud, Datadog, New Relic — through one pluggable
  connector registry with a schema-driven onboarding UI.
- **Deterministic detection** — JSON rule DSL, sliding windows, MITRE mapping, versioning and replay, Sigma import;
  findings are correlated into incidents without any LLM in the loop.
- **AI investigation you can audit** — Detection and Investigation Analyst agents (Gemini, Anthropic, OpenAI or any
  OpenAI-compatible endpoint incl. Ollama) work through an allowlisted tool broker, see masked data, and every claim in
  a verdict is grounding-checked against stored evidence. Agents hold no database or cloud credentials.
- **Human decision + learning** — approvals, analyst feedback and a knowledge base (trusted identities, known
  benign patterns) feed future investigations.
- **Built for isolation** — Postgres row-level security per organization, encrypted credential store, CSRF/RBAC,
  write-once raw evidence in S3-compatible storage, hash-chained audit log.
- **Self-hosted** — one Docker Compose stack; only the web UI is published. Backup, restore, upgrade and rollback scripts
  included.

### Connector status

| Connector | Status |
|---|---|
| GCP (Cloud Logging) | live-tested |
| AWS (CloudTrail, CloudWatch Logs) | adapter + fixtures, not live-tested |
| Azure (Activity Log, Entra ID, Defender) | adapter + fixtures, not live-tested |
| Datadog (Logs, Cloud SIEM, Audit Trail) | adapter + fixtures, not live-tested |
| New Relic (Logs via NRQL) | adapter + fixtures, not live-tested |

Help live-test a connector: `scripts/verify-<provider>-live.mts` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Install in 5 minutes

On a fresh Linux VM — Ubuntu 22.04/24.04, Debian 12, RHEL/Alma/Rocky 9 or Amazon Linux 2023, on AWS, Google Cloud,
Azure or anywhere else; 2 vCPU / 4 GiB minimum, 4 vCPU / 8 GiB recommended, 50 GiB disk:

```bash
curl -fsSL https://github.com/OneLab-X/vigil/releases/download/v0.1.0/get.sh | sudo bash -s -- --version 0.1.0
```

Prefer to read it first? `curl -fsSLO …/get.sh && less get.sh && sudo bash get.sh --version 0.1.0`.

`get.sh` installs Docker if needed, downloads the checksum-verified release bundle into `/opt/vigil`, generates secrets
locally, pulls the signed images, starts everything behind health checks, creates the first owner with a one-time
password and installs the `vigil` command (`vigil status | logs | backup | restore | upgrade | rollback | diagnostics |
uninstall`). Re-running it is safe. To run from a git checkout instead: `deploy/scripts/install.sh`.

See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) for configuration, TLS, backup/restore and upgrades.

## Architecture

- `apps/api` — control plane (Node/TypeScript, Hono, Zod, OpenAPI). Auth, RBAC, tenant isolation, connectors,
  ingestion worker, detection engine, incidents, **tool broker**, approvals, knowledge, audit.
- `apps/web` — dashboard (Next.js 15, Tailwind, TanStack Query, Recharts, lucide).
- `services/agents` — AI workers (Python/FastAPI): Detection Analyst + Investigation Analyst, provider abstraction
  (Anthropic via official SDK, OpenAI, Gemini). Holds no DB or cloud credentials.
- `packages/core` — provider-independent event model, connector registry (GCP, AWS, Azure, Datadog, New Relic) + normalizers, detection DSL/engine,
  seed rules, Sigma import, investigation contract + grounding validator, synthetic fixtures (test only).
- `packages/db` — Drizzle schema, migrations, RLS policies, grants.
- `deploy/` — Docker Compose install, operator scripts (install, preflight, diagnostics, backup, restore, upgrade, rollback).
- `docs/` — [self-hosting](docs/SELF_HOSTING.md), [AI data handling](docs/AI_DATA_HANDLING.md), [roadmap](docs/ROADMAP.md), [architecture](docs/ARCHITECTURE.md), [ERD](docs/ERD.md), [threat model](docs/THREAT_MODEL.md).

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Run locally (development)

Prereqs: Node 22 + pnpm 9, PostgreSQL 17 binaries with pgvector (`initdb`, `pg_ctl` on PATH), `uv`, `gcloud`.

```bash
pnpm install
pnpm db:start                 # isolated cluster in .local/pg on 127.0.0.1:54329, roles vigil_owner / vigil_app
pnpm db:migrate
pnpm db:seed                  # tenant "Example Security" + owner/analyst/reviewer/viewer; passwords → .local/dev-credentials.json
(cd services/agents && uv sync --python 3.13)
```

Start everything with one command (starts Postgres if needed, then api + agents + web with prefixed logs; Ctrl+C stops all three, Postgres keeps running — `pnpm db:stop` to stop it):

```bash
pnpm dev
```

Or start the processes individually (separate terminals):

```bash
pnpm dev:api                            # :8080, includes the ingestion/detection worker (watch mode)
pnpm dev:agents                         # :8090 — loads .env if present; needs GEMINI_API_KEY (paid tier) for real AI runs; default model gemini-4-argon
pnpm dev:web                            # :3000 — sign in with an account from .local/dev-credentials.json
```

OpenAPI: http://127.0.0.1:8080/api/v1/openapi.json

## Verify

```bash
pnpm --filter @vigil/core test          # normalization, detection, sigma, grounding, redaction, retry
pnpm --filter @vigil/api test           # RLS/cross-tenant, auth/CSRF/RBAC, broker hardening, full acceptance flow (GCP + AWS)
(cd services/agents && uv run pytest)   # agent loop: untrusted envelopes, allowlist, repair, budgets
node --experimental-strip-types scripts/verify-gcp-live.mts example-project 6 gcloud_cli   # LIVE, read-only; API must be running
# Same for the other connectors (credentials from env vars, never printed): scripts/verify-{azure,datadog,newrelic}-live.mts
```

Live GCP auth modes: `adc` (Application Default Credentials), `wif` (Workload Identity Federation config — production),
`gcloud_cli` (developer's gcloud token — local dev only, refused in production). Grant the reader
`roles/logging.viewer` (+ `roles/logging.privateLogViewer` for Data Access logs). Never upload service-account keys.

## Contributing, security, license

- Contributions welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off required) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
- Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
