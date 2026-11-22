# Architecture

## System boundaries

ChainProof starts as a modular monolith with explicit boundaries so high-volume ingestion and analysis workers can be extracted later without premature distributed-system complexity.

- Web application: dashboards, evidence review, and administration.
- API: authentication boundary, validation, authorization, domain orchestration, and audit emission.
- Domain modules (planned): organizations, projects, components, SBOMs, advisories, artifacts, attestations, policies, releases, incidents, and evidence.
- Workers (planned): asynchronous SBOM parsing, advisory synchronization, artifact verification, and report generation.
- Persistence: MongoDB for tenant-scoped domain records; Redis for queues and bounded coordination.
- Object storage: versioned evidence payloads and large source documents.

## Trust boundaries

1. Browser to API: TLS, strict origin policy, schema validation, authentication, and per-resource authorization.
2. API to database: least-privilege credentials and tenant-scoped repositories.
3. API to workers: validated, versioned job payloads and idempotency keys.
4. Workers to external registries: outbound allowlists, timeouts, size limits, retry budgets, and no execution of fetched content.
5. Artifact verification: digest and signature verification against explicit trust roots.

## Core data ownership

Every tenant-owned record will carry an organization identifier and be accessed through a tenant-aware repository boundary. Cross-tenant access must fail closed. Public advisory intelligence is logically separate from tenant-owned project and release data.

## Decision integrity

A release decision preserves the evaluated policy version, evaluation timestamp, subject digest, evidence references, and deterministic outcome. AI summaries are annotations only; they cannot mutate policy results or establish cryptographic validity.

## Evolution strategy

Start with a modular monolith and shared TypeScript contracts. Introduce separate workers when workload isolation, scaling, or security boundaries justify it. Keep external providers behind adapters.
