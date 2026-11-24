# Architecture

## System boundaries

ChainProof is currently implemented as a TypeScript modular monolith with explicit domain boundaries. This keeps deployment and operations simple while leaving room to extract workers or services when workload, scale, or isolation requirements justify it.

- Web application: React dashboard for inventory, evidence review, and administration.
- API: authentication boundary, validation, authorization, domain orchestration, and audit emission.
- Implemented capabilities: tenant-aware SBOM ingestion, vulnerability scans, artifact/provenance verification, release policy evaluation, signed passports, and signer lifecycle management.
- Persistence: MongoDB for tenant-scoped domain records and audit metadata.
- Planned evolution: asynchronous workers, Redis-backed queues, and object storage for large evidence payloads. These are not required components of the current runtime.

## System diagrams

See [System Architecture and Trust Flows](./SYSTEM-ARCHITECTURE.md) for:
- Runtime component and external-provider boundaries.
- SBOM-to-policy-to-passport evidence lifecycle.
- Offline Ed25519 verification and trust-store decisions.
- CLI examples, trust rules, and exit-code semantics.

## Trust boundaries

1. Browser to API: TLS, strict origin policy, schema validation, authentication, and per-resource authorization.
2. API to database: least-privilege credentials and tenant-scoped repositories.
3. API to external registries: bounded requests, timeouts, retry budgets, and no execution of fetched content.
4. Artifact verification: digest and signature verification against explicit server-side identity and builder policies.
5. Offline passport verification: authenticated trust-store distribution independent of the passport source.

## Core data ownership

Tenant-owned records are accessed through authenticated tenant context and tenant-aware query boundaries. Cross-tenant access must fail closed. Public advisory intelligence is logically separate from tenant-owned project and release data.

## Decision integrity

A release decision preserves its evaluated policy version, evaluation timestamp, subject digest, evidence references, and deterministic outcome. Cryptographic verification and signer trust are separate checks. AI summaries, if introduced, are annotations only; they cannot mutate policy results or establish cryptographic validity.

## Evolution strategy

Keep shared TypeScript contracts and external providers behind adapters. Introduce separate workers or services only when workload isolation, scaling, or security boundaries justify the operational cost.
