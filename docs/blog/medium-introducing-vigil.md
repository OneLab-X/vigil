# AI in the SOC Shouldn't Be a Black Box. So We Built One You Can Audit.

### Introducing Vigil: open-source, self-hosted security operations for your clouds — where AI investigates, evidence decides, and a human signs off.

---

Every security team I talk to has the same two problems.

The first is old: too many alerts, not enough people. Cloud audit logs never sleep. A single misconfigured service account, a burst of 404s against `/wp-admin`, a role assignment at 3 a.m. — each one *might* matter, and somebody has to pull the logs, line up the timeline, check whether the principal is a known automation, and write it up.

The second is new: everyone now wants to throw an LLM at the first problem. And the honest answer from most security engineers is *"Sure — but I can't trust what it tells me, I can't see what it saw, and I'm not handing it my cloud credentials."*

**Vigil** is our answer to both. It's an open-source (Apache-2.0), self-hosted platform that turns cloud signals into investigated, evidence-backed incidents — with AI doing the legwork and humans making the call.

Here's how it works, and more importantly, why it's built the way it is.

---

## The pipeline: from cloud signal to human decision

```
Cloud signals → ingestion → normalization → deterministic detection
  → correlation → AI investigation → evidence-backed verdict
  → human decision → organizational learning
```

Notice where the AI sits. It's *in the middle*, not at either end. It doesn't decide what's suspicious, and it doesn't decide what happens next. That's deliberate, and it shapes everything else.

### 1. Read-only, keyless connectors

Vigil pulls audit data from **GCP Cloud Logging, AWS CloudTrail and CloudWatch Logs, Azure (Activity Log, Entra ID, Defender for Cloud), Datadog, and New Relic** through a single pluggable connector registry.

Every connector is read-only and least-privilege. Where the cloud supports it, there are no long-lived keys at all: Workload Identity Federation on GCP, STS AssumeRole with an ExternalId on AWS, managed identity on Azure. When you test a connection, Vigil probes its own permissions and *warns you if it has any write access it doesn't need*.

The registry is schema-driven, too: a connector declares its config and credential fields, and the onboarding UI renders itself. Adding a new source doesn't mean touching the frontend.

### 2. Detection without an LLM in the loop

This is the part people are sometimes surprised by: **detection in Vigil is fully deterministic.**

Rules are written in a JSON DSL with sliding windows, mapped to MITRE ATT&CK, versioned, and replayable against historical data. You can import Sigma rules. Out of the box there are rules for things like:

- Service account or access-key creation (T1098.001)
- Security logging disabled or altered (T1562.008)
- Firewall or security-policy modification (T1562.007)
- AWS root account activity (T1078.004)
- Azure privileged role assignment (T1098.003)
- Repeated auth failures, port scans, 404 reconnaissance bursts

Findings are correlated into incidents — again, with no model involved. If a rule fires, you can explain exactly why. That's the foundation the AI builds on, not something it replaces.

### 3. AI investigation, on a short leash

Once an incident exists, two agents go to work: a **Detection Analyst** and an **Investigation Analyst**. They can run on Gemini, Anthropic, OpenAI, or any OpenAI-compatible endpoint — including a local Ollama or vLLM, in which case your evidence never leaves your network.

What they *can't* do is the interesting part.

**The agents hold no credentials.** The agent service has no database password and no cloud credentials. Its only route to data is a **tool broker** in the control plane. Each investigation gets an HMAC-signed run token that encodes the tenant, the agent's role, an allowlist of tools, and an expiry. The broker validates every argument, runs the query under the tenant's row-level-security context, caps result sizes, and logs every single call.

The toolset is narrow and read-oriented: `search_events`, `get_event_details`, `get_identity_activity`, `get_related_incidents`, `search_approved_security_knowledge`, and a handful more. The most "active" thing an agent can do is write an investigation note or *propose* a detection rule for a human to review.

**Log content is treated as hostile.** Attackers control a lot of what ends up in logs — user agents, URL paths, request bodies. Every tool result is wrapped as untrusted data before it reaches the model, so a cleverly crafted log line can't masquerade as instructions.

**Sensitive values are masked by default.** Before anything reaches the model, the broker replaces IPs, emails, principals, account IDs and resource names with consistent per-run tokens like `[[IP_3:public]]` or `[[SVC_1:gcp]]`. The model can still correlate and pivot — searching for `[[IP_3:public]]` resolves to the real IP inside the broker — but it never sees the raw value. The token map is stored encrypted and never leaves Vigil.

### 4. Verdicts that have to show their work

An agent doesn't get to just say "this is malicious." It has to submit a structured result: a verdict (`confirmed`, `likely`, `benign`, `inconclusive`, or `needs_more_data`), a confidence score, supporting evidence, *and contradictory evidence*.

Then Vigil checks it:

- **Every claim is grounding-checked.** Each piece of evidence must point to an event the agent *actually retrieved through the broker in this run*. If it cites a field value that doesn't match the real event, a timestamp that's off, or an IP address that appears in no retrieved event — the verdict is rejected.
- **Strong verdicts need evidence.** A `confirmed` or `likely` verdict with no evidence items fails validation. So does `confirmed` with confidence under 0.5.
- **Made-up tokens are treated as fabrication.** If the model references a masked token the run never issued, the result is thrown out.

Notice that "I don't know" is a first-class answer. `inconclusive` and `needs_more_data` don't require evidence, because an agent that's allowed to abstain is far less tempted to invent something.

### 5. A human decides — and the system learns

The verdict goes to an analyst for approval. Analyst feedback, along with a knowledge base of trusted identities and known-benign patterns, flows back into future investigations. That deploy bot that rotates keys every Tuesday? Mark it once, and the next investigation already knows.

Every step — every tool call, every approval, every decision to run an investigation unmasked — lands in a hash-chained audit log.

---

## Why self-hosted?

Because security telemetry is some of the most sensitive data a company has, and "send all your audit logs to our SaaS" is a hard sell for exactly the teams who need this most.

Vigil runs as a single Docker Compose stack. Only the web UI is published. Under the hood:

- **Postgres row-level security** per organization
- **Encrypted credential store** — API keys and secrets are write-only and never returned by the API
- **Write-once raw evidence** in S3-compatible storage
- **CSRF protection and role-based access control**
- **Built-in HTTPS** via a pinned Caddy proxy with automatic Let's Encrypt
- **Signed, multi-arch images** (cosign keyless, with SBOM attestations)

And it ships with the boring-but-essential operator tooling: backup, restore, upgrade, rollback and diagnostics, all behind a single `vigil` CLI.

---

## Running in five minutes

On a fresh Linux VM (Ubuntu, Debian, RHEL-family or Amazon Linux; 2 vCPU / 4 GiB minimum):

```bash
curl -fsSL https://github.com/OneLab-X/vigil/releases/download/v0.1.0/get.sh | sudo bash -s -- --version 0.1.0
```

Prefer to read a script before piping it to `sudo`? Good instinct — download it, read it, then run it. The installer sets up Docker if needed, verifies the release bundle against signed checksums, generates secrets locally, starts everything behind health checks, and creates your first owner account with a one-time password.

If you're on AWS, GCP or Azure, there are cloud quickstarts (cloud-init plus Terraform) that create the VM *and* attach the keyless identity each connector uses — so you never create or download a key.

---

## What's new since launch

Vigil 0.1.0 shipped on November 13, 2026. Since then:

- **Slack and email alerts** for new incidents and severity increases, with per-channel severity thresholds, optional entity redaction, retries, and flood control so a bad night doesn't become 400 notifications.
- **Member management** in the UI — add people, change roles, with guards against removing the last owner.

---

## Where it stands — honestly

Vigil is **pre-1.0**, and I'd rather tell you exactly what that means than have you find out:

- **GCP is live-tested.** AWS, Azure, Datadog and New Relic connectors are implemented with recorded fixtures and tests, but haven't yet been validated against live accounts. There are scripts in the repo (`scripts/verify-<provider>-live.mts`) to do exactly that, and help here is very welcome.
- **Masking is best-effort pseudonymization, not DLP.** It catches IPs, emails, identities, account and resource IDs. A person's name buried in a free-text log message won't be caught.
- **No automatic remediation, by design.** Vigil investigates and recommends. It doesn't touch your infrastructure.
- **No compliance certification is claimed.**

On the roadmap: streaming ingestion (Pub/Sub, Event Hubs, CloudWatch subscriptions), Splunk / Elastic / Sentinel connectors, SSO, an agent evaluation harness against real models, and external secrets managers.

---

## Get involved

Vigil is Apache-2.0 licensed and built in the open.

- ⭐ **GitHub:** [github.com/OneLab-X/vigil](https://github.com/OneLab-X/vigil)
- 🧪 **Help live-test a connector** — especially AWS, Azure, Datadog or New Relic
- 📏 **Write detection rules** — or bring your Sigma rules and tell us what breaks
- 🔒 **Found a vulnerability?** Report it privately through GitHub's security advisories

AI is going to be part of the SOC. The question is whether it shows up as a black box with admin rights — or as a careful junior analyst that cites its sources, admits when it doesn't know, and lets you make the call.

We're building the second one. Come build it with us.

---

*Tags: Cybersecurity · Cloud Security · Open Source · Artificial Intelligence · DevSecOps*
