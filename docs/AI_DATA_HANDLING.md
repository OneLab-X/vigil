# AI model configuration and data handling

Vigil's investigation agents call a large language model. You choose which one, where it runs, and whether
evidence may leave your infrastructure at all.

## What is sent to the model

For each investigation run the agent service sends, over the run's lifetime:

| Sent | Contents |
|---|---|
| System prompt | Vigil's fixed role instructions and the untrusted-data policy |
| Task | case id and the question (e.g. "Investigate CASE-0042…") |
| Tool results | results of the broker tools the agent calls: normalized security events, related incidents, approved knowledge entries, identity/resource activity, wrapped as `<untrusted_log_data>` |

Tool results include **IP addresses, URLs and paths, user agents, principals (emails, service accounts, ARNs),
resource names and timestamps** from your logs — with masking on (default), IPs, emails, identities, account ids and
resource names are replaced by tokens first (see below). Raw evidence returned by `get_event_details` is passed through
regex redaction (bearer tokens, JWTs, AWS keys, GCP API keys, private keys, card numbers) — this is best-effort
redaction, not a DLP guarantee.

Never sent: cloud credentials, database credentials, model API keys, session tokens, other organizations' data.

### Per-connector notes
Agents only ever see **normalized events** (and redacted raw payloads on request) from connectors you enabled:

| Connector | Log content that may reach the model |
|---|---|
| Datadog | Whatever the enabled queries match: log `message` text (regex-redacted, ≤8 KB), tags, host/service names and structured attributes (redacted, ≤16 KB per event) — e.g. client IPs, user ids/emails, URL paths and query strings, user agents; SIEM signal titles and entities; Audit Trail actor emails/IPs and asset names. Forwarded cloud records carry the same fields as direct cloud ingestion. Narrow the source queries (and base query) to security-relevant logs to limit what can reach a model; API/application keys never do. |
| New Relic | Same as Datadog for the rows your NRQL predicates match: `message` (redacted, ≤8 KB), hostname, service/entity name, log level and all row attributes (redacted, ≤16 KB) — client IPs, users, URLs, trace ids. Forwarded cloud records carry the same fields as direct cloud ingestion. The User API key never does. |
| Azure | Activity Log operations (caller UPN / object id, caller IP, resource ids, operation name, status, role-assignment role names); Entra ID sign-ins (UPN, IP, app, error codes, city/country, client app, Conditional Access result, risk level); Entra audit activity (initiator UPN/IP, target object names, role names); Defender alert titles, descriptions, entities (account, IP, host). Client secrets and access tokens are never part of events. With masking on, UPNs, IPs, subscription/tenant ids and resource ids are tokenized. |

## Masking (on by default)

With masking on, the tool broker replaces sensitive values with consistent per-run tokens **before** anything
reaches the agent service or the model, and restores them only inside Vigil:

| Masked | Token | Hint kept |
|---|---|---|
| IPv4 / IPv6 addresses | `[[IP_3:public]]` | scope: public / private / loopback / link_local / reserved |
| Email addresses | `[[EMAIL_1]]` | — |
| Identities (principals, ARNs) | `[[USER_2]]`, `[[SVC_1:gcp]]`, `[[ROLE_1:aws]]` | user / service account / role, cloud |
| Cloud project / account ids (incl. inside resource paths and free text) | `[[ACCOUNT_1:gcp]]` | cloud |
| Resource ids | `[[RESOURCE_5]]` | — |

Not masked (kept for analysis): event ids, timestamps, URL paths, HTTP methods/status, actions/API method names,
user agents, service names, regions, rule names. Free-text fields are scanned with the detectors above; anything they
do not recognise (e.g. a person's name in a log message) is not masked — this is best-effort pseudonymization, not DLP.

How it works:
- The same real value gets the same token for the whole run, so the model can correlate and pivot
  (`search_events` with `source_ip: "[[IP_3:public]]"` is resolved by the broker to the real IP).
- The token map is stored AES-GCM encrypted on the run and never returned by the API or sent to the model.
- The model's final result is unmasked before validation, so grounding checks, stored verdicts, notes and proposed
  rules contain real values. A token the run never issued is treated as fabrication and the result is rejected.
- The run's trace shows what the model saw (tokens) and counts of masked values per type.

Control: **Settings → AI models → Mask sensitive data** sets the organization default. On the incident page an admin
can choose **Run unmasked** for a single run (confirmation required; analysts can't), or **Run masked** when the default
is off. Each run records whether it was masked, and the choice is in the audit log.

## Where it goes

| Provider type | Data goes to | Notes |
|---|---|---|
| Gemini API (`gemini`) | Google (generativelanguage.googleapis.com) | use a paid-tier key; free-tier prompts may be used by Google to improve products |
| Anthropic API (`anthropic`) | Anthropic (api.anthropic.com) | server-side refusal fallback may route a declined request to another Anthropic model |
| OpenAI API (`openai`) | OpenAI (api.openai.com) | |
| OpenAI-compatible (`openai_compatible`) | the base URL you configure | Ollama, vLLM, LM Studio, LiteLLM, an internal gateway; when hosted by you, evidence stays in your network |

Review each vendor's data-processing terms against your obligations; Vigil makes no compliance claim about them.

## Configuring providers

**Settings → AI models** (admin/owner):
- *Provider*: type, base URL, API key (stored AES-256-GCM encrypted in the database, write-only — it is never
  shown again or returned by the API), hosting (`customer_hosted` / `external`), request timeout, and price per
  1M input/output tokens. External providers must have a price > 0 so the per-run USD budget is enforced;
  customer-hosted models may be priced at 0.
- **Test** sends one tiny request from the agent service (the same network position real runs use).
- *AI data policy*: `any`, `customer_hosted_only` (runs on external providers are refused before anything is
  sent), or `disabled`.

**Agent Governance → New version** picks the provider and model per agent role (task-specific model selection),
plus step, time, token and cost budgets. Every change is a new audited version.

Agents without a configured provider use keys set on the agent service (`GEMINI_API_KEY`, …) and count as
external.

### Run fully local with Ollama
1. Run Ollama on the Docker host (or any host the agent service can reach) and pull a tool-calling model,
   e.g. `ollama pull qwen3:32b` or `llama3.3:70b`. Small models often fail the structured-output contract;
   Vigil then reports the run as failed rather than accepting malformed output.
2. Settings → AI models → Add provider: type *OpenAI-compatible*, base URL `http://host.docker.internal:11434/v1`,
   hosting *customer-hosted*, prices 0.
3. Set the AI data policy to *customer-hosted only*.
4. Agent Governance → New version for both roles → select the provider and model.

## Safeguards
- Keys travel only from the API to the agent service on the internal Docker network for the duration of a run;
  the model and the tool broker never receive them, and the agent service never echoes request input in errors.
- Base URLs are checked against cloud-metadata and link-local addresses when saved and again (after DNS
  resolution) when the agent service connects. Private/LAN addresses are allowed for customer-hosted models.
- Log content is treated as untrusted data; verdicts must cite evidence the run actually retrieved, and every
  verdict and recommendation requires human approval.
