# Changelog

All notable changes to Vigil are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
Release notes for each GitHub release are taken from the matching section of this file.

## [Unreleased]

### Added
- Open-source project files: Apache-2.0 `LICENSE` and `NOTICE`, `CONTRIBUTING.md` (DCO sign-off), `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, issue/PR templates, `CODEOWNERS`, Dependabot, gitleaks config.

### Changed
- Test fixtures, docs and the dev seed use documentation placeholders (`example-project`, `Example Security`) instead
  of real project identifiers. Existing local dev databases keep their old demo tenant; `pnpm db:seed` now creates
  tenant slug `example`.

## [0.1.0] - 2026-11-12

First version. Not yet published as release images.

### Added
- Control plane API (Hono, OpenAPI), Next.js dashboard, Python agent workers.
- Connector registry with GCP (live-tested), AWS, Azure, Datadog and New Relic connectors.
- Deterministic detection engine (rule DSL, sliding windows, Sigma import, replay), correlation into incidents.
- AI investigation through an allowlisted tool broker with masking and grounding validation; human approvals and
  knowledge base.
- Postgres row-level security per organization, encrypted credential store, hash-chained audit log.
- Docker Compose single-organization install with preflight, install, backup, restore, upgrade, rollback and
  diagnostics scripts.

[Unreleased]: https://github.com/OneLab-X/vigil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OneLab-X/vigil/releases/tag/v0.1.0
