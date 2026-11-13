# Security Policy

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/OneLab-X/vigil/security/advisories/new>

Please include the affected version (`VERSION` or image tag), configuration, reproduction steps and impact. We will
acknowledge within 3 working days, agree a fix and disclosure timeline with you (default: fix within 90 days, sooner for
actively exploited issues), and credit you in the advisory unless you prefer otherwise.

In scope: everything in this repository — the API, web app, agent workers, connectors, database schema/RLS policies,
the Docker images we publish and the installer/operator scripts in `deploy/`. Of particular interest:

- cross-tenant data access or RLS bypass;
- credential or secret disclosure (stored cloud credentials, `VIGIL_SECRET_KEY`, session tokens);
- tool-broker escapes, prompt-injection that leads to actions without human approval;
- authentication, CSRF or RBAC bypass;
- installer behaviour that weakens host security (file modes, published ports, unverified downloads).

Out of scope: findings that require an already-compromised host or Docker daemon, denial of service by an
authenticated owner of the same instance, and missing hardening on third-party infrastructure you operate yourself.

## Supported versions

Vigil is pre-1.0. Security fixes are released for the **latest minor release** only; upgrade with
`deploy/scripts/upgrade.sh` (or `vigil upgrade` once the installer ships). Older minors receive fixes only for
critical issues, at the maintainers' discretion.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Hardening guidance

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md). Release images are
built in CI from tagged commits only.
