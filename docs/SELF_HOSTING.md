# Self-hosting Vigil

Vigil runs entirely on infrastructure you control. Nothing connects to a vendor-hosted service: the only outbound
connections are to the cloud APIs you connect (read-only), the AI model endpoint you configure, the container registry
and GitHub releases (install/upgrade only) and, with built-in HTTPS, Let's Encrypt.

Status: the Docker Compose install is the supported deployment for a single organization. Kubernetes/Helm, high
availability and air-gapped installs are on the [roadmap](ROADMAP.md) and are **not** available yet.

Contents: [Quick install](#1-quick-install) · [Requirements](#2-requirements-and-sizing) ·
[What gets installed](#3-what-gets-installed) · [Cloud guides](#4-cloud-guides) · [HTTPS](#5-https-and-network-exposure) ·
[Configuration](#6-configuration-reference) · [First login](#7-first-login) · [First source](#8-connect-your-first-source) ·
[Operations](#9-operations) · [Upgrades](#10-upgrades) · [Backup & restore](#11-backup-and-restore) ·
[Rollback](#12-rollback) · [Uninstall](#13-uninstall) · [Troubleshooting](#14-troubleshooting)

## 1. Quick install

On a fresh Linux VM (Ubuntu 22.04/24.04, Debian 12, RHEL/Alma/Rocky 9, Amazon Linux 2023), as a user with sudo:

```bash
curl -fsSL https://github.com/OneLab-X/vigil/releases/download/vX.Y.Z/get.sh \
  | sudo bash -s -- --version X.Y.Z --domain vigil.example.com --email ops@example.com \
      --admin-email you@example.com --admin-name "Your Name" --org "Example Ltd"
```

Replace `X.Y.Z` with a [release](https://github.com/OneLab-X/vigil/releases). To read the script before running it:

```bash
curl -fsSLO https://github.com/OneLab-X/vigil/releases/download/vX.Y.Z/get.sh
less get.sh
sudo bash get.sh --version X.Y.Z [options]      # sudo bash get.sh --help lists them all
```

`get.sh`:
1. checks it runs as root on a supported OS and installs Docker Engine + the Compose plugin from Docker's repositories
   if they are missing (skipped when present);
2. downloads `vigil-deploy-X.Y.Z.tar.gz` and `SHA256SUMS` for that release, verifies the checksum (and, when
   [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is installed, the Sigstore signature of
   `SHA256SUMS`), and unpacks it into `/opt/vigil` (`--data-dir` to change);
3. runs the preflight (Docker, Compose ≥ 2.24, CPU/memory, disk, ports, DNS when `--domain` is set) — read-only;
4. creates `/opt/vigil/.env` from `env.template` with secrets generated locally by `openssl` (mode 600);
5. pulls the release images (signature-verified with cosign when available), starts every service and waits until all
   health checks pass and `/readyz` is ok;
6. creates the first owner and shows the URL and a **one-time password** — on a terminal it is printed; in unattended
   runs (cloud-init, CI) it is written to `/opt/vigil/initial-owner-password` (root-only) instead of the log;
7. installs the `vigil` command.

Without `--domain` the UI listens on `127.0.0.1:3000` only (see [§5](#5-https-and-network-exposure)).

**Re-running is safe**: an existing installation keeps its `.env` (secrets — including `VIGIL_SECRET_KEY` — are never
regenerated), data and files; it only makes sure everything is running. There is no destructive overwrite: `--reset`
takes a full backup, moves the old directory to `/opt/vigil.reset-<timestamp>` and removes the old volumes, and only
after you type the host name (or set `VIGIL_RESET_CONFIRM=<hostname>` with `--yes`).

**From a git checkout** (development, or building images yourself): `deploy/scripts/install.sh` does steps 3–6 with
images built locally (`deploy/compose.build.yaml`) and `deploy/.env` instead of `/opt/vigil/.env`.

**Back up `.env`** somewhere safe and access-controlled. `VIGIL_SECRET_KEY` decrypts stored credentials (cloud WIF
configs, AI provider keys); without it a restored database cannot use them.

## 2. Requirements and sizing

| | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GiB | 8 GiB |
| Disk | 30 GiB (10 GiB free for a trial) | 50 GiB+, sized for retention (raw evidence + events) |
| OS (get.sh) | Ubuntu 22.04/24.04, Debian 12, RHEL/Alma/Rocky 9, Amazon Linux 2023 — x86_64 or arm64 | |
| Docker | Engine + Compose v2 **2.24+** (installed by `get.sh`) | latest |
| Network in | 80 + 443 with built-in HTTPS; nothing otherwise | |
| Network out | registry (`ghcr.io`), GitHub releases, your cloud APIs, your AI provider, Let's Encrypt | |

The preflight fails below 3 GiB of memory visible to Docker (a "4 GiB" VM reports slightly less) and warns below the
recommended size. macOS/Windows with Docker Desktop work for evaluation through `deploy/scripts/install.sh` from a checkout.

## 3. What gets installed

| Service | Image | Purpose | Reachable from |
|---|---|---|---|
| `web` | `ghcr.io/onelab-x/vigil-web` (release) or built from `deploy/docker/web.Dockerfile` (source) | Next.js UI; proxies `/api/v1` to the API | **published** on `VIGIL_WEB_BIND:VIGIL_WEB_PORT` (default `127.0.0.1:3000`) |
| `api` | `ghcr.io/onelab-x/vigil-api` / `deploy/docker/api.Dockerfile` | REST API, tool broker, RBAC, audit | internal network only |
| `worker` | same image as `api` | ingestion polling, detection, correlation, agent dispatch, timeouts | internal |
| `agents` | `ghcr.io/onelab-x/vigil-agents` / `deploy/docker/agents.Dockerfile` | AI investigation worker. Holds model keys only; no DB or cloud credentials | internal |
| `postgres` | `pgvector/pgvector:0.8.1-pg17` | all application data (row-level security per organization) | internal |
| `objectstore` | `chrislusf/seaweedfs:4.51` | S3-compatible, write-once raw evidence | internal |
| `proxy` (only with `VIGIL_DOMAIN`) | `caddy:2.11.9-alpine` | HTTPS termination, HTTP→HTTPS redirect, HSTS | **published** on 80/443; `web` is then not published at all |
| `migrate` | same image as `api` | one-shot: migrations + evidence bucket creation, runs before api/worker on every start | — |

Only `web` (or, with built-in HTTPS, `proxy`) publishes a port. The agent tool broker (`/internal/v1`) is not routed by the web proxy and the API
port is not published, so it cannot be reached from outside the Docker network.

The job queue is Postgres-backed (`FOR UPDATE SKIP LOCKED`); Redis is not required for a single-node install.

## 4. Cloud guides

Ready-made, provider-agnostic quickstarts live in [`deploy/cloud/`](../deploy/cloud/): a `cloud-init.yaml` you can paste
as user data, and a Terraform example that creates the VM, firewall (80/443 only), disk, static IP, optional DNS record
and — importantly — the **keyless identity** Vigil's connector for that cloud uses:

| Cloud | Guide | Identity |
|---|---|---|
| AWS EC2 | [deploy/cloud/aws](../deploy/cloud/aws/) | instance profile role that may only `sts:AssumeRole` into customer `vigil-reader*` roles (IMDSv2, hop limit 2) |
| Google Compute Engine | [deploy/cloud/gcp](../deploy/cloud/gcp/) | attached service account with `roles/logging.viewer` (ADC) |
| Azure VM | [deploy/cloud/azure](../deploy/cloud/azure/) | user-assigned managed identity with Monitoring Reader |
| Any other VM / on-prem | §1 above | workload identity federation config files, or per-connection credentials |

Long-lived cloud keys are never needed for the install itself, and the installer never asks for them.

## 5. HTTPS and network exposure

**Built-in HTTPS (recommended):** `get.sh --domain vigil.example.com [--email you@example.com]`, or set `VIGIL_DOMAIN`
(and `VIGIL_WEB_ORIGIN=https://vigil.example.com`) in `.env` and re-run `install.sh`. A pinned Caddy container
publishes 80/443, obtains and renews a Let's Encrypt certificate, redirects HTTP to HTTPS and sets HSTS; the `web`
container is then not published at all. Before installing, point the name's A/AAAA record at the VM and open 80/443 —
the preflight checks that the name resolves to this host (local addresses and the AWS/GCP/Azure metadata service; no
third-party "what is my IP" service) and that 80/443 are free.

| `VIGIL_TLS_MODE` | Certificate |
|---|---|
| `acme` (default with a domain) | Let's Encrypt via HTTP-01; `VIGIL_ACME_EMAIL` optional for expiry notices |
| `custom` | your PEM chain and key: `VIGIL_TLS_CERT_FILE`, `VIGIL_TLS_KEY_FILE` (or `get.sh --tls-mode custom --tls-cert … --tls-key …`) |
| `internal` | Caddy's local CA — private networks only; browsers warn until you trust it |
| `off` | no proxy (same as leaving `VIGIL_DOMAIN` empty) |

**Bring your own proxy / load balancer:** leave `VIGIL_DOMAIN` empty, keep `VIGIL_WEB_BIND=127.0.0.1`, put nginx,
Traefik or a cloud load balancer in front of port 3000 and set `VIGIL_WEB_ORIGIN` to the public `https://` origin.
Without any proxy, reach the UI through an SSH tunnel: `ssh -L 3000:127.0.0.1:3000 you@vm`, then open
`http://localhost:3000`. Session cookies are `Secure` in production, so the UI must be served over HTTPS except on
`localhost`.

## 6. Configuration reference

Configuration lives in `/opt/vigil/.env` (release install) or `deploy/.env` (source install) — always a file named
`.env`, mode 600, created from `env.template`. After editing it, apply with `sudo bash /opt/vigil/scripts/install.sh --yes`
(idempotent: restarts what changed). Upgrades add new settings with their defaults and never change existing values.

<!-- BEGIN ENV REFERENCE (generated by deploy/release/gen-env-docs.py from deploy/env.template; do not edit) -->

| Section | Variable | Default | Description |
|---|---|---|---|
| Release | `VIGIL_VERSION` | `0.1.0` | Installed Vigil version; images are pinned to it. Changed only by upgrade/rollback. |
| Release | `COMPOSE_PROJECT_NAME` | `vigil` | Docker Compose project name (prefix of container and volume names). |
| Images | `VIGIL_IMAGE_REGISTRY` | `ghcr.io/onelab-x` | Registry for release images (vigil-api, vigil-web, vigil-agents), always pinned to VIGIL_VERSION. Point it at a mirror that preserves cosign signatures (e.g. `cosign copy`) for restricted networks. |
| Images | `VIGIL_INSTALL_MODE` | *(empty)* | source = build images from a git checkout, release = pull prebuilt images. Empty = auto-detect. |
| Images | `VIGIL_VERIFY_SIGNATURES` | `auto` | Release image signature check with cosign: auto (verify if cosign is installed, warn otherwise), require, off. |
| Web UI | `VIGIL_WEB_BIND` | `127.0.0.1` | Address the web UI is published on when the built-in HTTPS proxy is off. Default: this host only (reach it over SSH or put your own TLS reverse proxy in front). With VIGIL_DOMAIN set the web UI is not published at all. |
| Web UI | `VIGIL_WEB_PORT` | `3000` | Host port for the web UI when the built-in HTTPS proxy is off. |
| Web UI | `VIGIL_WEB_ORIGIN` | `http://localhost:3000` | Public origin users browse to (used for CORS/cookies), e.g. https://vigil.example.com |
| Built-in HTTPS (Caddy) | `VIGIL_DOMAIN` | *(empty)* | Set to publish 80/443 with automatic HTTPS, HTTP->HTTPS redirect and HSTS. DNS must point at this host. |
| Built-in HTTPS (Caddy) | `VIGIL_TLS_MODE` | *(empty)* | acme = Let's Encrypt (default) \| custom = your cert/key files below \| internal = Caddy's local CA \| off |
| Built-in HTTPS (Caddy) | `VIGIL_ACME_EMAIL` | *(empty)* | Contact email for the ACME account (expiry notices). Optional. |
| Built-in HTTPS (Caddy) | `VIGIL_TLS_CERT_FILE` | *(empty)* | For VIGIL_TLS_MODE=custom: host path to the PEM certificate chain. |
| Built-in HTTPS (Caddy) | `VIGIL_TLS_KEY_FILE` | *(empty)* | For VIGIL_TLS_MODE=custom: host path to the PEM private key. |
| Secrets (generated) | `VIGIL_SECRET_KEY` | *generated at install (secret)* | 32-byte hex key: encrypts stored credentials and signs agent run tokens. Never change it on an existing install. |
| Secrets (generated) | `VIGIL_INTERNAL_TOKEN` | *generated at install (secret)* | Shared secret between the API's tool broker and the agent service. |
| Secrets (generated) | `POSTGRES_PASSWORD` | *generated at install (secret)* | Postgres superuser (backup/restore only). |
| Secrets (generated) | `VIGIL_OWNER_DB_PASSWORD` | *generated at install (secret)* | Migration/owner role (BYPASSRLS; migrations and SECURITY DEFINER system functions only). |
| Secrets (generated) | `VIGIL_APP_DB_PASSWORD` | *generated at install (secret)* | Runtime role (NOBYPASSRLS: every query is confined by row-level security). |
| Secrets (generated) | `VIGIL_S3_ACCESS_KEY` | *generated at install (secret)* | Evidence store access key (bundled store: generated; external S3: your key, or empty to use the host's identity). |
| Secrets (generated) | `VIGIL_S3_SECRET_KEY` | *generated at install (secret)* | Evidence store secret key (see VIGIL_S3_ACCESS_KEY). |
| Evidence storage | `VIGIL_S3_BUCKET` | `vigil-evidence` | Bucket for write-once raw evidence. Bundled SeaweedFS (S3-compatible) by default; for external S3 / GCS-interop / Ceph / MinIO set bucket, endpoint, region and the key pair above (see docs/SELF_HOSTING.md). |
| Evidence storage | `VIGIL_S3_ENDPOINT` | `http://objectstore:8333` | S3 endpoint; http://objectstore:8333 is the bundled store. |
| Evidence storage | `VIGIL_S3_REGION` | `us-east-1` | S3 region. |
| Ingestion | `VIGIL_MAX_PAGES_PER_JOB` | `50` | Maximum API pages one ingestion job fetches before yielding (bounds job duration and API usage). |
| Ingestion | `VIGIL_INGEST_LAG_MINUTES` | `5` | Incremental polls stop this many minutes before now so late-arriving cloud logs are not missed. |
| Cloud identity (read-only) | `VIGIL_GCP_CREDENTIALS_FILE` | *(empty)* | Google Cloud. Leave empty on Compute Engine/GKE: the GCP connector (auth mode ADC) uses the VM's attached service account (roles/logging.viewer, + roles/logging.privateLogViewer for Data Access logs) — no key file. Elsewhere: host path to a Workload Identity Federation credential config (keyless). Avoid service-account keys. |
| Cloud identity (read-only) | `VIGIL_AWS_PRINCIPAL_ARN` | *(empty)* | AWS principal Vigil runs as (shown in the customer onboarding trust policy). On EC2 this is the instance profile role (deploy/cloud/aws sets it); credentials come from IMDSv2 — never configure access keys. |
| Cloud identity (read-only) | `VIGIL_AZURE_FEDERATED_TOKEN_FILE` | *(empty)* | Azure workload identity federation outside Azure: host path to a short-lived OIDC token file kept fresh by your platform. On an Azure VM use the connector's "managed identity" auth mode instead — nothing to set here. |
| AI models (agent service only) | `VIGIL_DEFAULT_MODEL_PROVIDER` | `gemini` | Provider for newly created agent definitions (gemini, anthropic, openai, openai_compatible). |
| AI models (agent service only) | `VIGIL_DEFAULT_MODEL` | `gemini-4-argon` | Model for newly created agent definitions. Providers and models can also be configured in Settings → AI models. |
| AI models (agent service only) | `GEMINI_API_KEY` | *(empty)* | Optional provider keys, visible only to the agent service (never to the API, database or connectors). |
| AI models (agent service only) | `ANTHROPIC_API_KEY` | *(empty)* | Optional Anthropic API key (agent service only). |
| AI models (agent service only) | `OPENAI_API_KEY` | *(empty)* | Optional OpenAI API key (agent service only). |
| AI models (agent service only) | `VIGIL_GEMINI_THINKING_LEVEL` | *(empty)* | Optional Gemini thinking level override. |

<!-- END ENV REFERENCE -->

### External object storage (S3 and compatible)
Point `VIGIL_S3_ENDPOINT`/`VIGIL_S3_REGION`/`VIGIL_S3_BUCKET` and the access key pair at AWS S3, GCS (S3 interop),
Ceph or MinIO. Enable bucket versioning (and Object Lock if available) on that bucket; Vigil also refuses to
overwrite evidence (`If-None-Match: *`) and re-checks each object's SHA-256 on read. The bundled `objectstore`
service can then be left idle or removed from `compose.yaml`.

## 7. First login

Open the URL the installer printed and sign in with the owner email and the one-time password (unattended installs:
`sudo cat /opt/vigil/initial-owner-password`, then delete the file). You must set a new password before anything else is
accessible; the one-time password is not stored anywhere else in plain text. Lost it, or need one for another user?

```bash
cd /opt/vigil && sudo docker compose --env-file .env exec api vigil-admin reset-password --email you@example.com
```

Next: invite colleagues (Settings → Members), configure an AI provider (Settings → AI models) — investigations stay
deterministic-only until you do — and connect a source.

## 8. Connect your first source

*Connections → Add connection* walks you through each connector; the form is generated from the connector's schema and
shows the exact least-privilege roles and commands for the auth mode you pick. **Test** checks credentials, probes for
read-only access and flags anything over-privileged before you enable ingestion; **Sources** suggests log sources to
enable. Prefer keyless auth modes: ADC/WIF on GCP, STS AssumeRole on AWS, managed identity / workload identity on Azure.

### Google Cloud
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
   - **Managed identity (keyless)** — when Vigil runs on an Azure VM: give the VM a system- or user-assigned managed
     identity with the roles above and pick *Managed identity* (client ID = the user-assigned identity's client ID).
     Tokens come from the VM's Instance Metadata Service. [deploy/cloud/azure](../deploy/cloud/azure/) sets this up.
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

### AWS
Vigil assumes a read-only role in each AWS account with STS `AssumeRole` + a per-connection ExternalId — 1-hour
credentials, no access keys. The onboarding page shows the trust policy (principal = `VIGIL_AWS_PRINCIPAL_ARN`, the
role Vigil itself runs as; on EC2 the instance profile role from [deploy/cloud/aws](../deploy/cloud/aws/)) and the
read-only permissions policy (CloudTrail `LookupEvents`, CloudWatch Logs read).

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

## 9. Operations

| Task | Release install | Source install |
|---|---|---|
| Status + readiness | `sudo vigil status` | `deploy/scripts/vigil.sh status` |
| Logs | `sudo vigil logs api worker -f` | `deploy/scripts/vigil.sh logs …` |
| Diagnostics bundle (local only, secrets masked) | `sudo vigil diagnostics` | `deploy/scripts/diagnostics.sh` |
| New one-time password for a user | `cd /opt/vigil && sudo docker compose --env-file .env exec api vigil-admin reset-password --email user@example.com` | same in `deploy/` |
| Verify audit hash chains | `… exec api vigil-admin verify-audit` | |
| Re-hash a sample of stored evidence | `… exec api vigil-admin verify-evidence --sample 500` | |

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

## 10. Upgrades

```bash
sudo vigil upgrade --version X.Y.Z     # default: the latest release
```

`vigil upgrade` downloads the release bundle and verifies it like `get.sh`, takes a **consistent backup** (writers
paused), tags the running images `rollback-<version>`, installs the new compose file and scripts, adds any new `.env`
settings with defaults (existing values and secrets are untouched), pulls and verifies the new images, runs migrations
and waits for health and `/readyz`. It refuses downgrades (use rollback).

**Upgrade one minor version at a time** (0.1 → 0.2 → 0.3) unless the release notes say a jump is safe; `vigil upgrade`
asks for confirmation when you skip a minor or change major version. Read the [CHANGELOG](../CHANGELOG.md) first.

Source installs: `git pull` (or check out the new tag), then `deploy/scripts/upgrade.sh` — same steps, images built
locally.

## 11. Backup and restore

```bash
sudo vigil backup             # consistent: pauses api/worker for the duration
sudo vigil backup --online    # no pause; database and evidence may differ by in-flight writes
```
A backup directory (`/opt/vigil/backups/<UTC timestamp>/`, or `deploy/backups/…`) holds `db.dump` (pg_dump custom
format), `evidence.tar` (bundled object store), `env` (your `.env`) and `manifest.json` with SHA-256 of each file. It
contains secrets: copy it off the VM, encrypted and access-controlled (e.g. `tar czf - backups/<ts> | age -r … > …`).
With external object storage the evidence bucket is not included — protect it with the provider's versioning/replication.

**Restore** on the same or a **new** VM:

```bash
# new VM: install the SAME version first (any admin details; they are replaced by the backup)
curl -fsSL …/vX.Y.Z/get.sh | sudo bash -s -- --version X.Y.Z --yes --admin-email tmp@example.com --admin-name tmp --org tmp
sudo cp -r /path/to/backups/20261112T060000Z /opt/vigil/backups/
sudo vigil restore /opt/vigil/backups/20261112T060000Z
```

Restore verifies the manifest checksums, asks for confirmation, puts the backup's `.env` in place (the previous one is
kept as `.env.pre-restore`), replaces the database and bundled evidence, starts the stack (migrations run), then runs
`verify-audit` and `verify-evidence`. If the new VM uses a different domain, update `VIGIL_DOMAIN`/`VIGIL_WEB_ORIGIN`
afterwards and re-run `install.sh --yes`. Test restores regularly.

## 12. Rollback

```bash
sudo vigil rollback              # newest upgrade backup
sudo vigil rollback /opt/vigil/backups/<backup made by the upgrade>
```

Migrations are forward-only, so rollback = previous images + previous compose file + the database and evidence from the
backup the upgrade took. **Anything written after that upgrade is lost.** Release installs re-pull (and verify) the
previous images if the local `rollback-` tags are gone.

## 13. Uninstall

```bash
sudo vigil uninstall            # stop and remove containers; data volumes, .env and backups are kept
sudo vigil uninstall --purge    # also DELETE the database and evidence volumes (type the host name to confirm)
```

Both print where the backups and `.env` are; remove `/opt/vigil` and `/usr/local/bin/vigil` yourself when you no longer
need them. Source installs: `deploy/scripts/vigil.sh uninstall …`.

## 14. Troubleshooting

Start with `sudo vigil status` and `sudo vigil diagnostics` (writes a local, secret-masked archive — review it before
sharing).

| Symptom | Check |
|---|---|
| preflight: "Docker cannot see …/deploy" | Docker Desktop / Colima only share some folders (Colima: your home directory) with their VM; move Vigil there or add the folder to file sharing |
| install stops at "services did not become healthy" | `deploy/scripts/diagnostics.sh`, then `… logs migrate api` |
| `/readyz` schema not ok | the `migrate` service failed: `… logs migrate` |
| AI runs fail with "provider unavailable" | Settings → AI models → **Test**; for Ollama on the Docker host use `http://host.docker.internal:11434/v1` |
| AI runs refused with `ai_policy_violation` | the organization's AI data policy only allows customer-hosted models |
| GCP connection `degraded` | the credential has write permissions; use a `roles/logging.viewer`-only identity |
| `get.sh`: "checksum mismatch" | the download was corrupted or altered — do not install; retry, or compare with the release page |
| image signature verification FAILED | do not run the images; check you are pulling from `ghcr.io/onelab-x` (or a mirror that preserves signatures) and report it via [SECURITY.md](../SECURITY.md) |
| HTTPS: certificate not issued | DNS must point at this host and port 80 must be reachable from the internet: `sudo vigil logs proxy` |
| `vigil upgrade` says "skips minor versions" | upgrade through each minor release in turn unless the release notes say otherwise |
| AWS connector on EC2: "Could not load credentials" | IMDSv2 hop limit must be 2 so containers reach the instance profile (`aws ec2 modify-instance-metadata-options --http-put-response-hop-limit 2`) |
| Azure connector: "managed identity token unavailable" | Vigil is not on an Azure VM, the VM has no managed identity, or the client ID does not match a user-assigned identity on it |
