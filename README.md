# ChainProof

**Enterprise Software Supply Chain Security & Trust Intelligence Platform**

ChainProof helps engineering and security teams understand, verify, govern, and continuously improve the integrity of the software they ship. It brings software inventory, vulnerability intelligence, build provenance, policy decisions, and release evidence into one auditable workflow.

> **Project status:** Foundation phase · Architecture and delivery are being established.

## Product vision

Modern software delivery depends on a complex graph of open-source packages, build systems, CI identities, artifact registries, and external suppliers. ChainProof turns that graph into actionable, explainable release assurance.

The platform is designed around a central principle: **cryptographic verification and deterministic policy enforcement are authoritative; AI may explain evidence and recommend actions, but never substitutes for verification or policy decisions.**

## Core capabilities

- **Software inventory:** ingest and normalize CycloneDX and SPDX SBOMs.
- **Vulnerability intelligence:** correlate components with vulnerability advisories, severity, exploitability signals, and remediation guidance.
- **Build provenance:** validate artifact digests, attestations, signer identity, and SLSA-aligned provenance.
- **Release Trust Passport:** create a tamper-evident, reviewable assurance record for every release.
- **Policy-as-code:** evaluate configurable release controls and produce explainable pass, warn, or block decisions.
- **Supplier and component risk:** track ownership, criticality, exposure, and remediation across the dependency estate.
- **Incident and compliance workflows:** preserve evidence, decisions, exceptions, and audit history.
- **AI-assisted analysis:** summarize findings with evidence-linked explanations and human approval for consequential actions.

## Planned technology

- **Web:** React, TypeScript, Vite, Tailwind CSS, accessible component primitives, TanStack Query.
- **API:** Node.js, Express, TypeScript, Zod, structured logging.
- **Data and jobs:** MongoDB, Redis, BullMQ, object storage.
- **Integrations:** GitHub, OSV, NVD, CycloneDX, SPDX, Sigstore/Cosign.
- **Operations:** Docker, GitHub Actions, OpenTelemetry, metrics, and structured audit events.

The stack and integration boundaries will be finalized through implementation milestones; external integrations will be introduced behind explicit adapters.

## Architecture principles

1. Tenant isolation is enforced in the data-access layer, not only in UI logic.
2. Authorization is deny-by-default and evaluated for every protected resource.
3. Untrusted repositories and artifacts are never executed in the API process.
4. Ingestion is asynchronous, bounded, observable, and idempotent.
5. Every security decision records its policy version and supporting evidence.
6. Secrets are never committed; configuration is validated at process startup.
7. Security-sensitive operations are auditable and attributable.

## Repository layout

The repository is being established as a pnpm monorepo:

```text
apps/
  api/       Express API
  web/       React application
packages/
  config/    Shared tooling configuration
  contracts/ Shared API/domain contracts (planned)
docs/
  architecture/
  security/
infra/
```

## Development

Prerequisites and exact commands will be documented as the foundation milestone lands. Never place production credentials in local files committed to Git; use `.env.example` only for variable names and safe defaults.

## Roadmap

- [x] Repository created
- [ ] Milestone 1 — monorepo foundation, developer experience, baseline documentation
- [ ] Milestone 2 — application shell and design system
- [ ] Milestone 3 — identity, organizations, RBAC, and tenant isolation
- [ ] Milestone 4 — project and source-control intelligence
- [ ] Milestone 5 — SBOM ingestion and component inventory
- [ ] Milestone 6 — vulnerability intelligence and remediation workflows
- [ ] Milestone 7 — provenance verification and Release Trust Passport
- [ ] Milestone 8 — policy governance, evidence, and audit
- [ ] Milestone 9 — operational hardening and production readiness

## Security

Please do not report vulnerabilities in public issues. Follow the process in [SECURITY.md](SECURITY.md).

## License

License selection will be made before the first public release.


## Security and contribution guidance

- [Security policy](SECURITY.md) — responsible vulnerability reporting and project security expectations.
- [Contributing guide](CONTRIBUTING.md) — engineering standards and pull request expectations.

These documents describe intended safeguards and contribution practices; they do not imply that planned product controls are already implemented or independently verified.
