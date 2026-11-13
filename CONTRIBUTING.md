# Contributing to Vigil

Thanks for helping. Vigil is a security product, so the bar is: small, tested, reviewable changes that never weaken
tenant isolation, credential handling or the human-decision step. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before changing anything under `apps/api/src/{lib,services}`,
`packages/db` (RLS) or `deploy/`.

## Ground rules

- **Security issues are not filed as public issues.** See [SECURITY.md](SECURITY.md).
- Open an issue (bug, feature or connector request template) before large changes so the design can be agreed first.
- One logical change per pull request. Keep unrelated refactors out.
- Never commit real credentials, customer data, account/project ids or log samples. Fixtures use documentation
  values (`example-project`, `123456789012`, `203.0.113.0/24`, `example.com`). CI runs gitleaks on every PR.
- New connectors are read-only: least-privilege reader roles, short-lived/keyless credentials preferred, no
  write scopes. Add recorded fixtures and normalizer tests; mark them "not live-tested" until someone verifies them
  against a real account with `scripts/verify-<provider>-live.mts`.

## Development setup

Prerequisites: Node 22 + pnpm 9, PostgreSQL 17 binaries with pgvector (`initdb`, `pg_ctl` on `PATH`), `uv`,
Python 3.13. Docker is only needed for the self-hosted install in `deploy/`.

```bash
pnpm install
pnpm db:start        # isolated cluster in .local/pg on 127.0.0.1:54329
pnpm db:migrate
pnpm db:seed         # demo tenant + users; passwords written to .local/dev-credentials.json (mode 600)
(cd services/agents && uv sync --python 3.13)
pnpm dev             # api :8080, agents :8090, web :3000
```

## Tests

All of these must pass before review:

```bash
pnpm --filter @vigil/core test
pnpm --filter @vigil/api test          # needs pnpm db:start
pnpm typecheck
(cd services/agents && uv run pytest)
shellcheck -x deploy/scripts/*.sh deploy/docker/*.sh
docker compose -f deploy/compose.yaml --env-file deploy/env.template config -q
```

Add tests with every behaviour change: unit tests in `packages/core/test`, API/RLS/security tests in
`apps/api/test`, agent loop tests in `services/agents/tests`.

## Developer Certificate of Origin (DCO)

Vigil uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a CLA. By signing
off a commit you certify that you wrote it, or otherwise have the right to submit it under the Apache License 2.0.

Sign off every commit:

```bash
git commit -s -m "Describe the change"
```

This appends `Signed-off-by: Your Name <you@example.com>` using your git `user.name` / `user.email`. Pull requests
with unsigned commits fail the DCO check; fix them with `git rebase --signoff main` and force-push your branch.

## Pull requests

- Fill in the PR template: what changed, why, how it was tested, security impact.
- Update docs (`docs/`, `deploy/env.template` comments) and `CHANGELOG.md` under *Unreleased* for user-visible changes.
- A maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) reviews; changes covered by `CODEOWNERS` need that
  owner's approval.

## License

By contributing you agree your contributions are licensed under the [Apache License 2.0](LICENSE).
