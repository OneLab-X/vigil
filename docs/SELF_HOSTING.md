# Self-hosting Vigil

Vigil runs entirely on infrastructure you control. Nothing connects to a vendor-hosted service: the only
outbound connections are to the cloud APIs you connect (read-only) and the AI model endpoint you configure.

Status: the Docker Compose install below is the supported deployment for a single organization.
Kubernetes/Helm, high availability and air-gapped installs are on the [roadmap](ROADMAP.md) and are **not** available yet.

## 1. Requirements

| | Minimum | Recommended |
|---|---|---|
| Docker Engine (or Docker Desktop / Colima) + Compose v2 | Compose 2.20 | latest |
| CPU available to Docker | 2 | 4 |
| Memory available to Docker | 3 GiB | 8 GiB |
| Disk | 10 GiB free | sized for retention (raw evidence + events) |
| Tools on the host | bash, openssl, python3 (restore checksum check) | |

The image builds do not require BuildKit.

## 2. What gets installed

| Service | Image | Purpose | Reachable from |
|---|---|---|---|
| `web` | built from `deploy/docker/web.Dockerfile` | Next.js UI; proxies `/api/v1` to the API | **published** on `VIGIL_WEB_BIND:VIGIL_WEB_PORT` (default `127.0.0.1:3000`) |
| `api` | `deploy/docker/api.Dockerfile` | REST API, tool broker, RBAC, audit | internal network only |
| `worker` | same image as `api` | ingestion polling, detection, correlation, agent dispatch, timeouts | internal |
| `agents` | `deploy/docker/agents.Dockerfile` | AI investigation worker. Holds model keys only; no DB or cloud credentials | internal |
| `postgres` | `pgvector/pgvector:0.8.1-pg17` | all application data (row-level security per organization) | internal |
| `objectstore` | `chrislusf/seaweedfs:4.51` | S3-compatible, write-once raw evidence | internal |
| `migrate` | same image as `api` | one-shot: migrations + evidence bucket creation, runs before api/worker on every start | — |

Only `web` publishes a port. The agent tool broker (`/internal/v1`) is not routed by the web proxy and the API
port is not published, so it cannot be reached from outside the Docker network.

The job queue is Postgres-backed (`FOR UPDATE SKIP LOCKED`); Redis is not required for a single-node install.

## 3. Install

```bash
git clone <your Vigil release> vigil && cd vigil
deploy/scripts/install.sh
```

The installer:
1. runs `deploy/scripts/preflight.sh` (Docker, Compose version, CPU/memory, disk, port) — it changes nothing;
2. creates `deploy/.env` from `deploy/env.template` with random secrets (mode 600);
3. builds the images and starts every service, waiting until all health checks pass;
4. checks `/readyz` (database, schema, evidence store);
5. asks for the first administrator's email, name and organization, and prints a **one-time password**.
   Sign in and you are asked to set a new password before anything else is accessible.

Non-interactive: `deploy/scripts/install.sh --admin-email you@example.com --admin-name "Your Name" --org "Example Ltd"`.
Install-time overrides: `VIGIL_WEB_PORT=8443 VIGIL_WEB_BIND=0.0.0.0 VIGIL_WEB_ORIGIN=https://vigil.example.com deploy/scripts/install.sh`.

**Back up `deploy/.env`** somewhere safe and access-controlled. `VIGIL_SECRET_KEY` decrypts stored credentials
(cloud WIF configs, AI provider keys); without it a restored database cannot use them.

### TLS and network exposure
Vigil does not terminate TLS. Keep `VIGIL_WEB_BIND=127.0.0.1` and put your reverse proxy (nginx, Caddy, Traefik,
a cloud load balancer) in front, then set `VIGIL_WEB_ORIGIN` to the public `https://` origin. Session cookies are
`Secure` in production, so the UI must be served over HTTPS except on `localhost`.

## 4. Configuration reference (`deploy/.env`)

| Variable | Meaning |
|---|---|
| `VIGIL_WEB_BIND`, `VIGIL_WEB_PORT`, `VIGIL_WEB_ORIGIN` | UI listener and the origin users browse to |
| `VIGIL_SECRET_KEY` | 32-byte hex; encrypts stored secrets, signs agent run tokens |
| `VIGIL_INTERNAL_TOKEN` | shared secret between API and agent service |
| `POSTGRES_PASSWORD`, `VIGIL_OWNER_DB_PASSWORD`, `VIGIL_APP_DB_PASSWORD` | database superuser / migration owner / runtime role (runtime role cannot bypass row-level security) |
| `VIGIL_S3_ENDPOINT`, `VIGIL_S3_REGION`, `VIGIL_S3_BUCKET`, `VIGIL_S3_ACCESS_KEY`, `VIGIL_S3_SECRET_KEY` | evidence store (bundled SeaweedFS by default) |
| `VIGIL_GCP_CREDENTIALS_FILE` | host path to a Google credential file, mounted read-only (see below) |
| `VIGIL_AZURE_FEDERATED_TOKEN_FILE` | host path to a platform-projected OIDC token for Azure workload identity federation (see below) |
| `VIGIL_DEFAULT_MODEL_PROVIDER`, `VIGIL_DEFAULT_MODEL` | model for newly created agent definitions |
| `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | optional agent-service keys; providers can instead be configured in the UI |
| `VIGIL_MAX_PAGES_PER_JOB`, `VIGIL_INGEST_LAG_MINUTES` | ingestion tuning |

Apply changes with `docker compose --project-directory deploy -f deploy/compose.yaml --env-file deploy/.env up -d`.

### Google Cloud credentials
Vigil only reads logs. Create a dedicated service account with `roles/logging.viewer` (add
`roles/logging.privateLogViewer` only if you want Data Access audit logs). Prefer **Workload Identity Federation**
(an external-account JSON config, no key) or run Vigil on a GCE/GKE host with that service account attached
(leave `VIGIL_GCP_CREDENTIALS_FILE` empty). A service-account key file works but is the least preferred option.
The connection test flags any write permission it finds. The developer-only `gcloud_cli` mode is refused in production.

### Microsoft Azure
Vigil reads the subscription **Activity Log**, **Defender for Cloud alerts** and **Entra ID sign-in / audit logs**
(via Microsoft Graph or a Log Analytics workspace). It never writes to Azure.

1. Create an app registration for Vigil (`az ad app create --display-name vigil-reader`, then `az ad sp create --id <appId>`).
2. Grant read-only access — exactly these, nothing broader:
   | Scope | Role / permission | For |
   |---|---|---|
   | Subscription | **Monitoring Reader** (or Reader) | Activity Log, Defender alerts |
   | Microsoft Graph | **AuditLog.Read.All** (application) + admin consent | Entra ID sign-in & audit logs via Graph (sign-in logs need Entra ID P1/P2) |
   | Log Analytics workspace | **Log Analytics Reader** | Entra ID logs via `SigninLogs` / `AuditLogs` instead of Graph |
   ```bash
   az role assignment create --assignee <appId> --role "Monitoring Reader" --scope /subscriptions/<subscriptionId>
   az ad app permission add --id <appId> --api 00000003-0000-0000-c000-000000000000 --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role
   az ad app permission admin-consent --id <appId>
   ```
3. Authentication, in order of preference:
   - **Workload identity federation (keyless)** — add a federated credential to the app for the identity your
     Vigil host already has (AKS workload identity, GitHub/GitLab OIDC, any OIDC issuer), mount the projected token
     file and set `VIGIL_AZURE_FEDERATED_TOKEN_FILE`. Vigil exchanges it for short-lived tokens; nothing is stored.
   - **Client secret** — create a secret on the app (`az ad app credential reset --id <appId> --years 1`) and paste it
     into the connection form. It is encrypted in the secret store, never returned by the API, never logged, and
     scrubbed from every error. Rotate by recreating the connection.
   - `azure_cli` (developer's `az login`) is for local development only and is refused in production.

The connection test lists the caller's effective permissions on the subscription and flags **Owner, Contributor,
User Access Administrator** (any `*`, role-assignment, resource-group or NSG write) and any write-capable Graph
permission (`*.ReadWrite.*`, `Directory.AccessAsUser.All`, …) as **over-privileged**.

### Datadog
Vigil reads logs, Cloud SIEM signals and the Audit Trail through Datadog's **search** APIs only
(`POST /api/v2/logs/events/search`, `…/security_monitoring/signals/search`, `…/audit/events/search`). It never
sends data to Datadog and never changes pipelines, indexes, monitors or rules.

1. *Organization Settings → Service Accounts* → create `vigil-reader` with the **Datadog Read Only Role**
   (so no key it owns can exceed read access).
2. On that service account, create an **application key** and restrict its **scopes** to:
   | Scope | Needed for |
   |---|---|
   | `logs_read_data` | **required** — log search |
   | `security_monitoring_signals_read` | optional — Cloud SIEM signals preset |
   | `audit_logs_read` | optional — Audit Trail preset |
   Do not leave the key unscoped: an unscoped key inherits every permission of its owner.
3. Create an **API key** (*Organization Settings → API Keys*); it only identifies the org.
4. In Vigil: *Connections → Add connection → Datadog*, pick your site (`datadoghq.com`, `us3`, `us5`,
   `datadoghq.eu`, `ap1`, `ap2`, `ddog-gov.com`), an org label, indexes (`*` = all the key can read) and an optional
   base query (e.g. `env:prod`). Both keys are stored encrypted, never returned and scrubbed from errors.

**Test** validates the API key, runs a 1-record log search, and inspects the application key: a scoped key cannot
list application keys (expected); if it can, its scopes are read and anything beyond the list above — or an unscoped
key — is flagged **over-privileged**. **Sources** suggests presets (SIEM signals, Audit Trail, `source:cloudtrail`,
`source:gcp*`, `source:azure*`, web access, authentication); edit the query before enabling.
Paging uses the search cursor with explicit `from`/`to` bounds; `X-RateLimit-*` headers are honoured (429 retry
after reset, and a proactive pause when the window is exhausted). The log search API is rate limited per org —
prefer a few broad presets with a 5–15 minute poll interval over many narrow ones.

### New Relic
Vigil runs NRQL `SELECT` queries against the `Log` event type through NerdGraph
(`https://api.newrelic.com/graphql`, EU: `https://api.eu.newrelic.com/graphql`). It never writes to New Relic.

1. *Administration → User management* → create a dedicated user (e.g. `vigil-reader`) in a group with the
   **Read Only** role, granted on the account you want to monitor only.
2. As that user, *API keys → Create a key → Key type: **User***. The key starts with `NRAK-`.
   Admin keys (`NRAA-`), license/ingest keys (`…NRAL`), insert keys (`NRII-`) and browser keys (`NRJS-`) are rejected
   by the form — they either carry write/admin rights or cannot read.
3. In Vigil: *Connections → Add connection → New Relic* with region, account id and an optional NRQL `WHERE`
   predicate (e.g. `environment = 'prod'`). The key is encrypted, never returned and scrubbed from errors.

**Test** checks the key type, that NerdGraph can reach the account, and — when the key's user can read user
management — flags membership of admin/manager groups as **over-privileged** (User keys inherit their user's rights;
if the groups are not visible, the test reminds you to verify the user is read-only). **Sources** suggests presets
(forwarded CloudTrail / GCP / Azure, web access, authentication); edit the predicate before enabling.
Ingestion queries `SELECT * FROM Log WHERE … SINCE <ms> UNTIL <ms> LIMIT MAX` over contiguous windows: a window
that returns the 5,000-row cap (or times out) is halved and re-queried, so nothing is silently truncated; overlap
from the scheduler is removed by `messageId` / content-hash dedupe.

### External object storage
Point `VIGIL_S3_ENDPOINT`/`VIGIL_S3_REGION`/`VIGIL_S3_BUCKET` and the access key pair at AWS S3, GCS (S3 interop),
Ceph or MinIO. Enable bucket versioning (and Object Lock if available) on that bucket; Vigil also refuses to
overwrite evidence (`If-None-Match: *`) and re-checks each object's SHA-256 on read. The bundled `objectstore`
service can then be left idle or removed from `compose.yaml`.

## 5. Operations

| Task | Command |
|---|---|
| Status | `docker compose --project-directory deploy -f deploy/compose.yaml --env-file deploy/.env ps` |
| Logs | `… logs -f api worker agents` |
| Diagnostics bundle (local only, secrets masked) | `deploy/scripts/diagnostics.sh` |
| New one-time password for a user | `… exec api vigil-admin reset-password --email user@example.com` |
| Verify audit hash chains | `… exec api vigil-admin verify-audit` |
| Re-hash a sample of stored evidence | `… exec api vigil-admin verify-evidence --sample 500` |

Health endpoints: `api` `/healthz` (process up) and `/readyz` (database, schema version, evidence store; agent
service reported but optional); the worker writes a heartbeat checked by its container health check.

### Operations page

**Operations** in the web console (`/operations`, API `GET /api/v1/operations/overview?window=1h|24h|7d|30d`) shows
system health for the active tenant. It needs the `operations:read` permission, which only **admins and owners**
have; viewers and analysts don't see the menu entry and get `403` from the API. All tenant figures are read
under row-level security, so one tenant never sees another tenant's sources, jobs, costs or latency. The page
refreshes every 30 s while the browser tab is visible.

| Section | What it shows | Thresholds / meaning | What to do |
|---|---|---|---|
| Component health | Database, schema/migrations, evidence store, AI agents service (from `/readyz`), background worker | Worker is **ok** if a heartbeat arrived in the last 5 min (written every 30 s), **stale** otherwise, **unknown** if none was ever recorded. The agents service is optional: when it's down, AI investigations stop but ingestion and detection continue | `down`: check `… logs api`, database/object-store reachability, run `deploy/scripts/diagnostics.sh`. `stale` worker: `… ps worker`, `… logs worker`, restart the worker |
| Ingestion lag | Per log source: now − checkpoint watermark (newest event time fully ingested), last successful job, last error | **healthy**; **lagging** = watermark older than `VIGIL_OPS_LAG_THRESHOLD_MINUTES` (default 30; override per request with `lagThresholdMinutes`); **failing** = most recent finished job failed; **never run**; **disabled** | Lagging: check the worker is alive and the queue isn't backed up; incremental polls run every `poll_interval_seconds` and stop `VIGIL_INGEST_LAG_MINUTES` before now, so a few minutes of lag is normal. Failing: read the error, then re-test the connection under **Cloud Connections** (credentials, permissions, API quota) |
| Job queue | Jobs by type × status (done jobs only within the window), oldest runnable queued job, running, stuck, retrying, dead-lettered | **Stuck** = running with a lock older than 10 min (the queue reclaims these automatically). **Dead-lettered** = `failed` after `max_attempts` retries | A growing oldest-queued age means the worker can't keep up or isn't running. Stuck jobs repeating usually mean a job is crashing the worker — check worker logs. Dead-lettered jobs need the underlying error fixed; they aren't retried |
| Failures | Failed jobs, ingestion jobs and investigation runs (failed/timeout/rejected) in the last 24 h and 7 d, plus the 20 most recent errors | Error text is sanitized (URLs, credentials, tokens and keys removed) and truncated to 300 characters | Use the error to find the component; full context is in the service logs |
| API latency | p50/p95/p99, request count and 5xx/4xx rate per route group, plus a time series | Recorded by API middleware as per-minute histograms per route *template* (e.g. `/incidents/:id`) — never raw paths, query strings, bodies or IPs. Only tenant-bound requests are counted. Percentiles are estimates from fixed buckets (5 ms … 10 s). Kept 7 days, so a 30-day window shows 7 days | Sustained p95 above ~1 s or a 5xx rate above 1 %: check database load and `… logs api` |
| AI cost | Total model spend, tokens, average and p95 cost per **completed** investigation, breakdown by provider/model | From `model_usage`; computed with SQL numeric and returned as fixed 6-decimal USD strings | Unexpected spend: review agent budgets under **Agent Governance** and model prices under **Settings → AI models** |
| Storage | Security events, raw evidence objects and bytes for this tenant; whole-database size | Database size is shared by all tenants and needs `CONNECT` on the database; if the app role isn't allowed it is shown as "—" | Plan disk/object-store growth; tenant event retention is set by `retention_days` |

The endpoint is designed to answer in well under 300 ms: every query is bounded by a time window or `LIMIT`
and uses indexes added in migration `0007_operations`. There is no Prometheus/OpenTelemetry exporter yet;
the latency recorder (`apps/api/src/lib/latency.ts`) keeps its aggregates behind a small interface so one can be
added later.

## 6. Backup and restore

```bash
deploy/scripts/backup.sh            # consistent: pauses api/worker for the duration
deploy/scripts/backup.sh --online   # no pause; database and evidence may differ by in-flight writes
```
A backup directory (`deploy/backups/<UTC timestamp>/`) holds `db.dump` (pg_dump custom format), `evidence.tar`
(bundled object store), `env` (your `deploy/.env`) and `manifest.json` with SHA-256 of each file. It contains secrets:
store it encrypted. With external object storage the evidence bucket is not included — protect it with the
provider's versioning/replication.

```bash
deploy/scripts/restore.sh deploy/backups/20261112T060000Z
```
Restore verifies the manifest checksums, asks for confirmation, replaces the database and bundled evidence,
starts the stack (migrations run), then runs `verify-audit` and `verify-evidence`.

## 7. Upgrade and rollback

```bash
git pull            # or unpack the new release over this directory (deploy/.env and backups are kept)
deploy/scripts/upgrade.sh
```
Upgrade takes a consistent backup, keeps the current images tagged `rollback-<version>`, builds the new version,
runs migrations and waits for health and readiness. Migrations are forward-only, so rolling back restores the
pre-upgrade backup:

```bash
deploy/scripts/rollback.sh deploy/backups/<backup made by upgrade.sh>
```
Anything written after the upgrade's backup is lost on rollback.

## 8. Uninstall

```bash
docker compose --project-directory deploy -f deploy/compose.yaml --env-file deploy/.env down        # keep data volumes
docker compose --project-directory deploy -f deploy/compose.yaml --env-file deploy/.env down -v     # also DELETE all data
```

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| preflight: "Docker cannot see …/deploy" | Docker Desktop / Colima only share some folders (Colima: your home directory) with their VM; move Vigil there or add the folder to file sharing |
| install stops at "services did not become healthy" | `deploy/scripts/diagnostics.sh`, then `… logs migrate api` |
| `/readyz` schema not ok | the `migrate` service failed: `… logs migrate` |
| AI runs fail with "provider unavailable" | Settings → AI models → **Test**; for Ollama on the Docker host use `http://host.docker.internal:11434/v1` |
| AI runs refused with `ai_policy_violation` | the organization's AI data policy only allows customer-hosted models |
| GCP connection `degraded` | the credential has write permissions; use a `roles/logging.viewer`-only identity |
