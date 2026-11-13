# Governance

Vigil is maintained by the people listed in [MAINTAINERS.md](MAINTAINERS.md) under the
[OneLab-X](https://github.com/OneLab-X) GitHub organization.

- **Decisions** are made by lazy consensus on issues and pull requests. If maintainers disagree, the change waits; if
  consensus is not reached in a reasonable time, a simple majority of maintainers decides.
- **Security-sensitive changes** (auth, RLS, tool broker, credential storage, installer) need approval from at least one
  maintainer other than the author.
- **Releases** are cut by a maintainer by tagging `vX.Y.Z` on `main`; CI builds, signs and publishes images and release
  assets. `CHANGELOG.md` is the source of release notes.
- **Becoming a maintainer:** sustained, high-quality contributions and reviews; nominated by an existing maintainer and
  approved by majority. Inactive maintainers (no activity for 12 months) move to emeritus.
- **Code of conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). **Security:** [SECURITY.md](SECURITY.md).
