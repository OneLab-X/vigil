# Changelog

All notable changes to Vigil are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
Release notes for each GitHub release are taken from the matching section of this file.

## [Unreleased]

### Added
- Open-source project files: Apache-2.0 `LICENSE` and `NOTICE`, `CONTRIBUTING.md` (DCO sign-off), `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, issue/PR templates, `CODEOWNERS`, Dependabot, gitleaks config.

- Release pipeline: `.github/workflows/release.yml` builds multi-arch (amd64/arm64) images
  `ghcr.io/onelab-x/vigil-{api,web,agents}`, tagged `X.Y.Z` and `X.Y`, signed with cosign keyless, with SPDX SBOM
  attestations; release assets `compose.yaml`, `env.template`, `vigil-deploy-X.Y.Z.tar.gz`, `SHA256SUMS` (signed).
- CI: core/api tests against Postgres, typecheck, web build, agents pytest, shellcheck, compose validation, image pin
  check, gitleaks, DCO.
- Operator scripts: `--help` everywhere; release mode pulls images and verifies signatures with cosign when installed
  (`VIGIL_VERIFY_SIGNATURES=auto|require|off`); source mode builds via `deploy/compose.build.yaml`.

### Changed
- `deploy/compose.yaml` references registry images (`VIGIL_IMAGE_REGISTRY`); local builds moved to
  `deploy/compose.build.yaml`. Source installs keep their `vigil/<service>` image names.
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
