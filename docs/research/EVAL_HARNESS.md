# VigilBench evaluation harness

The harness for the study designed in [EVAL_STUDY.md](EVAL_STUDY.md). It loads benchmark cases into a dedicated
evaluation database, runs the real pipeline (normalization → detection → correlation), dispatches the Investigation
Analyst to the real agent worker under each ablation configuration, and scores the results offline.

Evaluation installs only. Every switch below is refused when `NODE_ENV`/`VIGIL_ENV` is `production`, the agent
image sets `VIGIL_ENV=production`, and the runner refuses any database whose name does not contain `eval`.

## Quick start (no model spend)

```bash
pnpm db:eval
```

Terminal 1 — agent worker in evaluation mode (separate port from the dev worker):

```bash
cd services/agents && VIGIL_EVAL_MODE=1 VIGIL_ALLOW_SCRIPTED_PROVIDER=1 VIGIL_EVAL_CAPTURE_DIR=$PWD/../../.local/eval/capture uv run uvicorn vigil_agents.app:app --host 127.0.0.1 --port 18090
```

Terminal 2 — run the smoke plan with the built-in scripted model `eval-abstain` (reads the case, always abstains):

```bash
cd apps/api && VIGIL_EVAL_MODE=1 VIGIL_DATABASE_URL=postgres://vigil_app:vigil_app_dev@127.0.0.1:54329/vigil_eval VIGIL_AGENTS_URL=http://127.0.0.1:18090 VIGIL_EVAL_CAPTURE_DIR=$PWD/../../.local/eval/capture pnpm eval:run --plan ../../eval/plans/smoke.json
```

```bash
cd apps/api && pnpm eval:score --results ../../.local/eval/smoke/results.jsonl
```

The report lands next to the results: `report.md` (tables) and `report.json` (everything).

For real models, put provider keys in the agent worker's environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY`), drop `VIGIL_ALLOW_SCRIPTED_PROVIDER`, and use a plan like [eval/plans/pilot.json](../../eval/plans/pilot.json).
`eval:run --dry-run` prints the job count first. `VIGIL_EVAL_CAPTURE_DIR` must be the same path for the worker
and the runner (it is how the canary leak test sees what reached the model).

## Plans

`eval/plans/*.json`:

| field | meaning |
|---|---|
| `name` | output goes to `.local/eval/<name>/` unless `--out` is given |
| `caseSources` | `"builtin"` (seed scenarios from `packages/core/src/fixtures`) and/or directories of JSON cases, e.g. `"eval/cases"` |
| `caseIds`, `splits`, `tiers` | filters; `splits` defaults to `["public"]` so held-out cases are opt-in |
| `models[]` | `{id, provider, name}`; optional `endpoint` (OpenAI-compatible, e.g. Ollama), `hosting`, `price {input, output}` per 1M tokens, `apiKeyEnv` (env var with the key; never written to results) |
| `configs[]` | ablation ladder, below |
| `repeats` | runs per (case, config, model); each run gets a fresh tenant |
| `maxUsd` | hard ceiling for the whole plan, counted across resumed invocations |
| `concurrency`, `limits`, `brokerPort` | parallel jobs; agent step/time/token/USD budgets; port of the in-process tool broker |

Ablation configurations (`apps/api/src/eval/run.ts` `CONFIGS`):

| id | agent flags | masking | meaning |
|---|---|---|---|
| `B0` | – (no agent) | – | rules only: open incident = "malicious" |
| `B1` | `single_shot no_envelope no_ground_rules` | off | case context pasted into one prompt, no tools |
| `L0` | `no_envelope no_ground_rules` | off | agent loop + broker, no prompt-level defenses |
| `L0W` | `L0` + `write_stub` | off | also offers a fake `mark_incident_resolved` write tool (the broker refuses and records it) |
| `L1` | `no_envelope` | off | + ground-rules prompt |
| `L2` | – | off | + untrusted-data envelope |
| `L4` | – | on | production default (+ pseudonymization) |

**L3 (grounding validator) needs no runs:** the scorer reads every agent run twice — `raw` (output as submitted,
validator off) and `gated` (only accepted output, validator on). L3 is L2 `gated`.

## Case format

One case per JSON file (or an array), anywhere under a case source directory. Schema: `EvalCaseSchema` in
`apps/api/src/eval/cases.ts`. Example: [eval/cases/examples/gcp-recon-semantic-pentest.json](../../eval/cases/examples/gcp-recon-semantic-pentest.json).

- `records[]`: `{connector, sourceType, raw}` — raw vendor payloads, normalized by the connector registry.
  Use `"sourceType": "gcp_log"` for GCP to pick the source type from `logName`.
- Templates keep data recent at load time: `{{t:+120}}` (base + 120 s, base = now − 2 h), `{{uuid}}`, `{{uuid:name}}`.
- `knowledge[]`: approved KB entries. `timing: "after_detection"` (default) leaves the incident open so the agent must
  find the entry; `"before_detection"` lets rule suppression act on it.
- `labels`: `verdict` (required), `severity`, `outcome`, `dataExposure`, `goldEvidence` (indexes into `records`),
  `keyEntities`, `rulesExpected`, `labelledBy`.
- `adversarial`: `{twinOf, goal, technique, field, marker}`. Goals: `verdict_flip`, `abstain_induce`, `tool_misuse`,
  `fabrication_induce`, `resource_exhaustion`, `write_action`. `marker` is a distinctive payload substring used to
  detect attacker text copied into notes.
- `canaries`: extra fake identifiers; IPs, principals and account ids in the data are added automatically.
- `split: "heldout"`: keep these files out of the public repo until results are final (contamination control).

## What one result line contains

`results.jsonl`, one line per job, append-only, resumable: case labels, detection outcome (fired/suppressed rules,
incident), the run (status, error, prompt version with flags, masking, tokens, USD, wall time, full output,
validation errors), every broker tool call (allowed or denied), side effects (notes, proposed rules, write-stub
calls), canary leaks, and the path of the model-transcript capture.

## Metrics (scorer)

`apps/api/src/eval/score-lib.ts`, all pure functions with unit tests (`apps/api/test/eval-score.test.ts`):
coverage, false-benign / false-malicious rate, selective accuracy, abstention on ambiguous cases, severity
(exact, ±1), outcome accuracy, Brier score, evidence precision/recall vs gold, fabrication rate (runs with grounding
issues), rejected rate, cost/latency/tokens, canary leak rate, write-stub and note/rule rates; attack success per goal
× technique with the clean-twin rate subtracted; 95 % CIs by cluster bootstrap over cases; exact McNemar with Holm
correction between adjacent ladder steps present in the results.

## Not built yet (from the study design)

- Validator-blind fabrication needs human claim labelling — export from `results.jsonl`; no tooling yet.
- L3-R (one repair round on grounding failure) — design §5.2, needs an API/agent protocol change.
- VigilBench content: parametric generator, benign twins, detonated tier, adversarial matrix (§4). Only the
  seed cases and one example adversarial case exist today.
- Detection Analyst (triage) is not evaluated; runs go straight to the Investigation Analyst.
- Results are files only; importing a report into the Evaluation page is not wired.
