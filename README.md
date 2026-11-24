# ChainProof

**Enterprise Software Supply Chain Security & Trust Intelligence Platform**

> Turn software composition, build provenance and security policy evidence into explainable release assurance.

## 1. Product vision

ChainProof is designed to help engineering and security teams inventory software components, correlate vulnerability intelligence, verify build provenance and govern release decisions through auditable evidence.

**Trust principle:** cryptographic verification and deterministic policy enforcement are authoritative. AI-assisted analysis may explain evidence or suggest remediation, but it must never replace signature verification, policy evaluation or accountable human approval.

## 2. Project status

**Status: foundation and milestone-driven portfolio development.** Capabilities described here represent the product scope and should be considered implemented only when present on the selected branch with tests and CI evidence. The dashboard gallery contains synthetic illustrative SVGs, not screenshots from a live deployment.

## 3. Core capabilities

- **SBOM inventory:** ingest and normalize CycloneDX and SPDX software bills of materials.
- **Vulnerability intelligence:** correlate components with advisories, severity, exploitability context and remediation guidance.
- **Build provenance:** verify artifact digests, signer identity, attestations and SLSA-aligned provenance.
- **Release Trust Passport:** assemble reviewable, evidence-backed assurance records for releases.
- **Policy-as-code:** evaluate versioned controls and return explainable pass, warn or block outcomes.
- **Dependency risk:** understand transitive dependency relationships, criticality and ownership.
- **Supplier governance:** track supplier and component risk, exceptions and remediation.
- **Incident evidence:** preserve correlated findings, decisions and investigation history.
- **AI-assisted explanation:** produce evidence-linked summaries with human oversight for consequential actions.

## 4. Technology direction

- Web: React, TypeScript, Vite and Tailwind CSS.
- API: Node.js, Express, TypeScript and Zod.
- Data and jobs: MongoDB, Redis/BullMQ and object storage where enabled.
- Integrations: GitHub, OSV, NVD, CycloneDX, SPDX and Sigstore/Cosign adapters.
- Operations: Docker, GitHub Actions, structured logs and OpenTelemetry-oriented observability.

Confirm actual package versions and enabled integrations from the checked-out branch and environment configuration.

## 5. Architecture and security principles

1. Enforce tenant isolation and authorization in service and data-access layers.
2. Never execute untrusted repositories, build scripts or uploaded artifacts inside the API process.
3. Make ingestion asynchronous, bounded, observable and idempotent.
4. Record policy version, signer identity, evidence references and decision rationale.
5. Treat SBOMs and attestations as untrusted input until schema and cryptographic checks pass.
6. Keep credentials in a secret manager; use references rather than raw secrets in workflow definitions.
7. Separate AI explanations from trusted verification and release-policy decisions.
8. Make security exceptions time-bound, attributable and reviewable.

## 6. Repository layout

The project is organized as a monorepo with API and web applications, shared tooling/contracts, infrastructure and architecture/security documentation. Refer to the selected branch for the current exact layout.

## 7. Local development

1. Install the Node.js and package-manager versions declared by the workspace.
2. Review `.env.example` files and configure local-only credentials and services.
3. Install dependencies using the committed lockfile and repository package manager.
4. Start only the local services documented for the selected milestone.
5. Run the scripts declared by root and application manifests.
6. Run typecheck, tests, build and relevant security checks before proposing a merge.

Do not commit provider tokens, private keys, signing material, production SBOMs or confidential source metadata.

## 8. Verification and release-quality strategy

- Validate SBOM schemas and normalize package identifiers before correlation.
- Verify artifact digest and signature against trusted identity policy.
- Preserve provenance and policy evaluation inputs for reproducibility.
- Test malformed, oversized and adversarial ingestion payloads.
- Exercise tenant boundaries, exception expiry and policy-version changes.
- Monitor dependency advisories and keep CI actions and build tooling maintained.

## 9. Illustrative dashboard gallery

The 12 SVGs below are **illustrative dashboard concepts**, not production screenshots. All values, components and events are synthetic. The single-column gallery is intended for full-width review.

### 01 — Software supply chain command center
A high-level view of component exposure, release assurance and verification activity.
![ChainProof software supply chain command center](docs/assets/dashboard/01-software-supply-chain-command-center.svg)

### 02 — SBOM inventory explorer
A component inventory concept for CycloneDX/SPDX coverage and dependency lineage.
![ChainProof SBOM inventory explorer](docs/assets/dashboard/02-sbom-inventory-explorer.svg)

### 03 — Vulnerability intelligence
An advisory triage view for severity context, exposure and remediation priority.
![ChainProof vulnerability intelligence](docs/assets/dashboard/03-vulnerability-intelligence.svg)

### 04 — Build provenance verification
A verification workspace for artifact digests, signer identity and attestations.
![ChainProof build provenance verification](docs/assets/dashboard/04-provenance-verification.svg)

### 05 — Release trust passport
An evidence-backed release assurance summary with policy evaluation context.
![ChainProof release trust passport](docs/assets/dashboard/05-release-trust-passport.svg)

### 06 — Policy-as-code workbench
A view of versioned controls, evaluation outcomes and explainable release decisions.
![ChainProof policy-as-code workbench](docs/assets/dashboard/06-policy-as-code-workbench.svg)

### 07 — Dependency risk graph
A conceptual view of transitive dependencies and critical package exposure.
![ChainProof dependency risk graph](docs/assets/dashboard/07-dependency-risk-graph.svg)

### 08 — Supplier risk workspace
A governance view of component ownership, supplier criticality and remediation.
![ChainProof supplier risk workspace](docs/assets/dashboard/08-supplier-risk-workspace.svg)

### 09 — Artifact integrity monitor
A monitor for digest drift, signature status and artifact verification events.
![ChainProof artifact integrity monitor](docs/assets/dashboard/09-artifact-integrity-monitor.svg)

### 10 — Security exception governance
A workflow for time-bound exceptions, approvers and compensating controls.
![ChainProof security exception governance](docs/assets/dashboard/10-security-exception-governance.svg)

### 11 — Incident evidence timeline
A timeline concept for correlated alerts, investigation notes and evidence references.
![ChainProof incident evidence timeline](docs/assets/dashboard/11-incident-evidence-timeline.svg)

### 12 — Compliance assurance report
A summary of control coverage, evidence freshness and audit-ready release signals.
![ChainProof compliance assurance report](docs/assets/dashboard/12-compliance-assurance-report.svg)

## 10. Documentation and contribution

Review `docs/architecture` and `docs/security` for current design decisions. Follow [SECURITY.md](SECURITY.md) for responsible disclosure and [CONTRIBUTING.md](CONTRIBUTING.md) for engineering and pull-request expectations.

## 11. Roadmap themes

- Expand SBOM ingestion and component normalization coverage.
- Improve provenance verification and trusted-builder policy.
- Add reproducible policy evaluations and richer release evidence.
- Strengthen ingestion sandboxing, tenant isolation and abuse controls.
- Improve end-to-end coverage, observability and operational recovery.

## 12. License

No open-source license is applied unless a license file is present. All rights are otherwise reserved.

## 11. Runnable web dashboard (foundation milestone)

The React/Vite dashboard now lives in `apps/web`. It provides tenant login, API health visibility and a tenant-scoped SBOM metadata workspace. The SBOM form stores validated metadata only; it does not upload or parse CycloneDX/SPDX documents, scan vulnerabilities, or verify provenance.

Run the API and web development server in separate terminals:

```bash
npm install
npm run dev
npm run dev:web
```

Open `http://localhost:5173`. The Vite server proxies `/api` requests to the local API on port 4000.

For a production-style local build:

```bash
npm run build
npm start
```

The API serves `apps/web/dist` at its root when that build exists. Access tokens are held in browser memory and are cleared on refresh/sign-out. Provision a user with the operator-only `npm run user:create` command before signing in.

## 12. Inventory search, export and integrity metadata

The tenant-scoped SBOM inventory supports document-name search and CycloneDX/SPDX filtering. Authorized users can export up to 5,000 tenant records as CSV. CSV values are escaped and spreadsheet formula prefixes are neutralized. An optional SHA-256 digest can be recorded; duplicate digests are rejected within the same tenant. A digest is metadata only at this stage and is not verified against an uploaded file.

## 13. Automated validation

Run the API and frontend test suite with:

```bash
npm test
npm run typecheck
npm run build
```

The tests cover SBOM validation, tenant-scoped queries, digest conflicts, CSV escaping/formula protection, JWT account revalidation, role authorization, and dashboard rendering. GitHub Actions runs tests, type checks, and production builds on pushes and pull requests.


## Container workflow

A local Docker Compose stack runs the API/web application with MongoDB. It is intended for development and portfolio demonstrations, not as a hardened production deployment.

```bash
# Create a local-only secret (keep .env out of version control).
printf 'JWT_SECRET=%s\n' "$(openssl rand -base64 48)" > .env

docker compose up --build -d
docker compose ps
docker compose logs -f app
```

Open http://localhost:4000. The API readiness endpoint is available at `/api/health/ready`; Compose waits for MongoDB to pass its health check before starting the app. MongoDB is reachable only on the Compose network and its data is stored in a named volume. Stop the stack with `docker compose down`; this preserves the database volume.

The image uses a multi-stage Node build and runs as the unprivileged `node` user. For production, use a managed MongoDB deployment with authentication and TLS, a managed secret store, restricted network ingress, backups, monitoring and an explicit deployment review. Do not reuse local secrets in production.
