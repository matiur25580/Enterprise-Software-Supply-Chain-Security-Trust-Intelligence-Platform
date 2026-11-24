# Architecture

## System boundaries

ChainProof is currently implemented as a TypeScript modular monolith with explicit domain boundaries.

- Web application: React dashboard for inventory, evidence review, and administration.
- API: authentication boundary, validation, authorization, domain orchestration, and audit emission.
- Implemented capabilities: tenant-aware SBOM ingestion, vulnerability scans, artifact/provenance verification, release policy evaluation, signed passports, signer lifecycle management, and durable asynchronous SBOM processing.
- Persistence: MongoDB for tenant-scoped domain records, audit metadata, and durable SBOM ingestion jobs.
- Background processing: the API enqueues bounded raw JSON; an in-process worker applies official CycloneDX/SPDX schema validation, complexity checks, normalization, and idempotent persistence. Raw job payloads are removed at terminal state.
- Planned evolution: independently deployed worker processes, streaming uploads, Redis coordination, and object storage for large evidence payloads.

## System diagrams

See [System Architecture and Trust Flows](./SYSTEM-ARCHITECTURE.md) for runtime boundaries, SBOM-to-passport evidence lifecycle, offline verification decisions, CLI examples, and operational trust rules.

## Trust boundaries

1. Browser to API: TLS, strict origin policy, authentication, role authorization, and bounded JSON request bodies.
2. API to database: least-privilege credentials and tenant-scoped repositories. Pending async jobs temporarily contain raw SBOM JSON up to 2 MiB and must be protected as source data.
3. API to worker: tenant ownership is assigned from authenticated context; the worker validates the queued document and removes raw input on completion or failure.
4. API to external registries: bounded requests, timeouts, retry budgets, and no execution of fetched content.
5. Offline passport verification: authenticated trust-store distribution independent of the passport source.

## Core data ownership

Tenant-owned records are accessed through authenticated tenant context and tenant-aware query boundaries. Cross-tenant access must fail closed. Public advisory intelligence is logically separate from tenant-owned project and release data.

## Decision integrity

A release decision preserves its evaluated policy version, evaluation timestamp, subject digest, evidence references, and deterministic outcome. Cryptographic verification and signer trust are separate checks. AI summaries, if introduced, are annotations only; they cannot mutate policy results or establish cryptographic validity.

## Evolution strategy

Keep shared TypeScript contracts and external providers behind adapters. Extract workers into independently deployed processes only when workload isolation, scaling, or security boundaries justify the operational cost.
