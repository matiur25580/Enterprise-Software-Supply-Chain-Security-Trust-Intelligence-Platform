# ChainProof

**Enterprise Software Supply Chain Security & Trust Intelligence Platform**

ChainProof helps engineering and security teams understand, verify, govern, and continuously improve the integrity of the software they ship. It brings software inventory, vulnerability intelligence, build provenance, policy decisions, and release evidence into one auditable workflow.

> **Project status:** Early implementation · Enterprise foundation, security command center, persistent identity, tenant-scoped project registry, GitHub App repository linking, bounded SBOM ingestion, and initial OSV vulnerability intelligence are implemented in draft milestone branches. Dashboard metrics remain illustrative sample data.

## Product vision

Modern software delivery depends on a complex graph of open-source packages, build systems, CI identities, artifact registries, and external suppliers. ChainProof turns that graph into actionable, explainable release assurance.

**Cryptographic verification and deterministic policy enforcement are authoritative; AI may explain evidence and recommend actions, but never substitutes for verification or policy decisions.**

## Core capabilities

- Software inventory: ingest and normalize CycloneDX and SPDX SBOMs.
- Vulnerability intelligence: correlate components with vulnerability advisories, severity, exploitability signals, and remediation guidance.
- Build provenance: validate artifact digests, attestations, signer identity, and SLSA-aligned provenance.
- Release Trust Passport: create a tamper-evident, reviewable assurance record for every release.
- Policy-as-code: evaluate configurable release controls and produce explainable pass, warn, or block decisions.
- Supplier and component risk: track ownership, criticality, exposure, and remediation across the dependency estate.
- Incident and compliance workflows: preserve evidence, decisions, exceptions, and audit history.
- AI-assisted analysis: summarize findings with evidence-linked explanations and human approval for consequential actions.

## Technology

- Web: React, TypeScript, Vite, Lucide icons, responsive component architecture, and accessible semantic UI.
- API: Node.js, Express, TypeScript, Zod, Mongoose, structured logging.
- Data and jobs: MongoDB, Redis, BullMQ, object storage.
- Integrations: GitHub, OSV, NVD, CycloneDX, SPDX, Sigstore/Cosign.
- Operations: Docker, GitHub Actions, OpenTelemetry, metrics, and structured audit events.

## Current implementation

- Enterprise pnpm/Turborepo workspace with React/Vite web application and Express API.
- Security command center with illustrative posture metrics, risk distribution, posture trend, prioritized findings, and recent activity.
- MongoDB identity models, organization registration, organization-scoped login, short-lived signed access tokens, hashed opaque refresh-token rotation, replay-triggered revocation, and logout.
- Every authenticated request checks persisted session, user, organization, and membership; effective roles come from active membership state.
- Tenant-scoped project registry with bounded listing, create/read/update/archive operations, organization-scoped MongoDB filters, strict validation, audit events, and a live React workspace for project lifecycle management.
- GitHub App installation verification, selected-repository discovery, tenant-safe project linking, and installation lifecycle webhook reconciliation.
- Bounded project-scoped CycloneDX 1.x and SPDX 2.x JSON SBOM ingestion, normalized component metadata, SHA-256 duplicate detection, and audit events.
- OSV.dev vulnerability scanning by versioned PURL, advisory detail enrichment, CVSS v3 scoring, fixed-version recommendations, and tenant-scoped findings.
- Authentication routes use strict Zod validation and IP-based rate limiting. MongoDB registration transactions require a replica-set deployment.
- MFA, SSO, email verification, password recovery, invitations, and production-grade GitHub App installation administration remain future work.

## Architecture principles

1. Tenant isolation is enforced in the data-access layer, not only in UI logic.
2. Authorization is deny-by-default and evaluated for every protected resource.
3. Untrusted repositories and artifacts are never executed in the API process.
4. Ingestion is asynchronous, bounded, observable, and idempotent.
5. Every security decision records its policy version and supporting evidence.
6. Secrets are never committed; configuration is validated at process startup.
7. Security-sensitive operations are auditable and attributable.

## Repository layout

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

Copy `.env.example` to a local environment file, start a MongoDB replica set, then run `pnpm install` and `pnpm dev`. Never commit production credentials.

## Roadmap

- [x] Repository created
- [x] Milestone 1 — monorepo foundation, developer experience, baseline documentation
- [x] Milestone 2 — application shell and design system
- [ ] Milestone 3 — identity, organizations, RBAC, and tenant isolation (persistent identity and session lifecycle foundation implemented; enterprise account controls remain)
- [ ] Milestone 4 — project and source-control intelligence (tenant-scoped project registry foundation implemented)
- [x] Milestone 5 — GitHub App integration foundation, tenant repository linking, and bounded SBOM ingestion foundation
- [ ] Milestone 6 — vulnerability intelligence and remediation workflows
- [ ] Milestone 7 — provenance verification and Release Trust Passport
- [ ] Milestone 8 — policy governance, evidence, and audit
- [ ] Milestone 9 — operational hardening and production readiness

## Security

Please do not report vulnerabilities in public issues. Follow the process in [SECURITY.md](SECURITY.md).

## License

License selection will be made before the first public release.


## Tenant-scoped project registry UI

The Projects workspace now authenticates against the ChainProof API and supports searchable active/archived project lists, project creation, metadata editing, and soft archival. It displays repository metadata and any verified GitHub repository links already associated with the selected project. Tenant ownership is always derived by the API from the authenticated session. Configure `VITE_API_BASE_URL` as described in [Web project registry](docs/architecture/WEB-PROJECT-REGISTRY.md).

## GitHub source-control integration foundation

The API now exposes a signed GitHub webhook intake endpoint at `POST /api/v1/webhooks/github`. Configure `GITHUB_WEBHOOK_SECRET` from GitHub App settings to enable it. The endpoint validates the raw-body HMAC-SHA256 signature, bounds request size and header values, and records idempotent delivery metadata with a payload fingerprint. It intentionally does not persist raw payloads, access tokens, or repository contents, and does not automatically bind installations to tenants. See [GitHub source-control integration architecture](docs/architecture/GITHUB-SOURCE-CONTROL-INTEGRATION.md).

This is webhook ingress foundation only; installation authorization, encrypted token custody, repository linking and background reconciliation remain follow-on work.


## GitHub App installation foundation

Milestone 5 now includes an owner/admin-authorized GitHub App installation start flow, signed short-lived state, one-time nonce consumption, current membership revalidation and a pending-verification installation record. Configure `GITHUB_APP_SLUG` to enable the install URL. See [GitHub App installation architecture](docs/architecture/GITHUB-APP-INSTALLATION.md). Installation records remain pending until a future provider-verification worker validates them through GitHub's App API; no token or private key is stored.


## GitHub App verification and repository discovery

ChainProof can verify a pending GitHub App installation against GitHub's App API using a short-lived RS256 App JWT, require selected-repository mode and read-only Contents/Metadata permissions, then discover installed repositories with an ephemeral installation token. Set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` through a deployment secret manager; never commit credentials. See [GitHub App installation architecture](docs/architecture/GITHUB-APP-INSTALLATION.md). Repository-to-project linking and source ingestion are not yet implemented.

### GitHub repository linking

Verified GitHub App installations can discover repositories and link selected repository IDs to tenant-owned projects. ChainProof validates every selection against GitHub's current installation inventory and stores provider metadata only. Signed installation suspend/delete webhooks update linked repository status. Source ingestion and SBOM analysis are subsequent milestones. See [GitHub App installation and repository linking](docs/architecture/GITHUB-APP-INSTALLATION.md).


## SBOM ingestion foundation

Projects accept JSON CycloneDX 1.x and SPDX 2.x SBOMs up to 2 MiB. ChainProof validates and normalizes up to 5,000 components per document, stores package identifiers and license metadata, fingerprints the original bytes with SHA-256, rejects duplicate uploads within a project, and emits an audit event. The raw SBOM is not retained. See [SBOM ingestion architecture](docs/architecture/SBOM-INGESTION.md). This is an initial synchronous ingestion slice; asynchronous processing, full dependency graph persistence, schema conformance, EPSS/KEV/NVD enrichment, and scheduled rescans remain future work.


## Vulnerability intelligence foundation

ChainProof can scan an ingested project SBOM against OSV.dev using versioned package URLs. The integration batches package queries, fetches full advisory records, maps advisories back to individual components, derives CVSS v3.0/v3.1 base scores where vectors are supplied, and stores affected/fixed version data with remediation guidance. Tenant-scoped scan and findings APIs are available. Scans are bounded and fail closed on upstream errors; unsupported CVSS v4 vectors are not guessed. See [Vulnerability intelligence architecture](docs/architecture/VULNERABILITY-INTELLIGENCE.md).


## Web SBOM and vulnerability workspace

The Components and Vulnerabilities screens now authenticate against the ChainProof API, list active projects and SBOM inventories, upload CycloneDX/SPDX JSON, trigger OSV scans, and display live project-scoped findings with severity, CVSS score, fixed versions, and remediation guidance. Configure `VITE_API_BASE_URL` for the API origin (defaults to `http://localhost:4000`). The web client keeps access/refresh tokens in memory only; access-token refresh is not yet automatic. See [Web SBOM workspace](docs/architecture/WEB-SBOM-WORKSPACE.md).


### GitHub App connection workspace

The Projects workspace can start GitHub App installation, refresh and verify pending installations, discover repositories from an active installation, and link a selected provider repository to an active project. The API exposes tenant-scoped installation metadata; repository metadata is sourced from GitHub, not browser input. See [WEB-GITHUB-CONNECTION.md](docs/architecture/WEB-GITHUB-CONNECTION.md).
