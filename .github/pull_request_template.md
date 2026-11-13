## What and why

<!-- What does this change and why? Link the issue: Fixes #… -->

## How it was tested

- [ ] `pnpm --filter @vigil/core test`
- [ ] `pnpm --filter @vigil/api test`
- [ ] `(cd services/agents && uv run pytest)`
- [ ] `pnpm typecheck`
- [ ] Manual check (describe):

## Security impact

<!-- Does this touch auth, RLS/tenant isolation, credential storage, the tool broker, AI data handling or deploy/?
     If yes, explain why the security model is unchanged or strengthened. Write "none" otherwise. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`, DCO)
- [ ] No real credentials, account/project ids, customer names or log samples in code, fixtures or docs
- [ ] Docs / `deploy/env.template` / `CHANGELOG.md` (Unreleased) updated for user-visible changes
