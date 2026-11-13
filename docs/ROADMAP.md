# Roadmap

Status of the product-strategy requirements (spec §13–25). "Done" means implemented, tested and documented —
not merely designed.

| Area | Status | Notes |
|---|---|---|
| Docker Compose single-organization install, S3-compatible evidence, health checks | **Done** | [SELF_HOSTING.md](SELF_HOSTING.md) |
| Install / preflight / diagnostics / first-admin / backup / restore / upgrade / rollback scripts | **Done** | `deploy/scripts/` |
| Customer-controlled AI providers (Gemini, Anthropic, OpenAI, OpenAI-compatible incl. Ollama), data policy | **Done** | [AI_DATA_HANDLING.md](AI_DATA_HANDLING.md) |
| Licensing & entitlements (signed offline license files, editions, limits, grace period) | Planned (before GA) | central entitlement service; historical evidence never locked |
| Guided onboarding checklist; source states (connected / discovered / enabled / healthy / failing) | Planned (before commercial beta) | |
| Operations page (ingestion lag, queue depth, failures, API latency, cost per investigation, storage) | **Done** | [SELF_HOSTING.md §5 Operations page](SELF_HOSTING.md#operations-page); `GET /api/v1/operations/overview`; admins/owners only |
| Connector SDK: registry, versioning, health reporting, fixtures kit | Partial | registry (`ConnectorDefinition`, `GET /api/v1/connectors`, schema-driven UI), scenario fixtures kit (`fixtures/scenarios.ts`), shared windowed paging + log-platform normalizer; GCP/AWS/Azure/Datadog/New Relic registered; per-connector health reporting pending |
| Push / streaming ingestion (webhooks, Event Hubs, log forwarding) | Planned | `ConnectorDefinition.streaming` reserved; `startStreaming` on the connector contract |
| Splunk / Elastic / Microsoft Sentinel connectors | Planned | same registry; Sentinel can reuse the Azure Log Analytics windowed KQL path |
| Rule export; rule approval workflow UI | Partial | import, Sigma subset, versioning, replay done |
| Agent evaluation datasets against real models | Partial | detection replay done; agent eval harness pending |
| AWS live validation, GuardDuty / Security Hub | Planned | adapter written, not live-tested |
| New Relic connector (Logs via NerdGraph NRQL, cloud-payload delegation) | **Done** (fixtures) · live validation pending | `scripts/verify-newrelic-live.mts` |
| Datadog connector (Logs search, Cloud SIEM signals, Audit Trail; cloud-payload delegation) | **Done** (fixtures) · live validation pending | `scripts/verify-datadog-live.mts`; log forwarding/streaming planned |
| Azure connector (Activity Log, Entra ID sign-in/audit, Defender for Cloud) | **Done** (fixtures) · live validation pending | `scripts/verify-azure-live.mts`; Event Hubs streaming planned |
| Streaming ingestion (Pub/Sub sink, CloudWatch subscription) | Planned | sink creation stays an admin-approved step |
| Retention scheduling | Planned | SQL function exists, not scheduled |
| External secrets managers (Vault, GCP/AWS Secret Manager) | Planned | `SecretStore` interface ready |
| SAML/OIDC SSO, SCIM, custom roles | Planned (Enterprise) | |
| Audit / compliance evidence exports | Planned | hash-chained audit log exists |
| Customer-managed encryption keys | Planned where practical | |
| Kubernetes / Helm, HA, horizontal scaling | Deferred until validated demand | |
| Air-gapped installation | Deferred until validated demand | requires pre-pulled images + local model |
| MSP multi-customer workflows | Deferred until a validated design partner | data model is tenant-scoped with RLS already |

No compliance certification is claimed.
