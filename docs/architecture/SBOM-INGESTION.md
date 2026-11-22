# SBOM ingestion foundation

## Supported input

The project-scoped API accepts JSON CycloneDX (1.x) and SPDX (2.x) documents up to 2 MiB. Parsing is synchronous and bounded in this first ingestion slice:

- CycloneDX component trees are flattened with a maximum nesting depth of 32 and 5,000 components.
- SPDX packages are normalized with the same 5,000 component maximum.
- Normalized inventory retains package name, group, version, package URL (PURL), CPE, license identifiers, and provider BOM/package reference.
- The original document is hashed with SHA-256. The raw document is not stored.
- Duplicate document digests are rejected within the same organization and project.
- Invalid JSON, unsupported formats, nameless components, malformed nested data, excessive depth, and component-limit violations are rejected.

## API

All endpoints require an active bearer session, organization scope, and project permission.

- `POST /api/v1/organizations/:organizationId/projects/:projectId/sboms` — upload a JSON SBOM; requires `projects:write`. Use `Content-Type: application/json` and send the SBOM document itself as the body.
- `GET /api/v1/organizations/:organizationId/projects/:projectId/sboms?limit=50` — list project SBOM metadata; requires `projects:read`.
- `GET /api/v1/organizations/:organizationId/projects/:projectId/sboms/:sbomId` — retrieve normalized inventory; requires `projects:read`.

The organization ID is always derived from authenticated membership. Every database lookup includes that organization and project. Ingestion emits an organization-scoped audit event containing the document digest and component count.

## Security and operational boundaries

- Raw upload bodies are limited to 2 MiB and parsed as JSON; no archive extraction, repository checkout, package installation, or code execution occurs.
- Only normalized component metadata and the SHA-256 fingerprint are retained; source SBOM contents are not persisted.
- Duplicate uploads are idempotently rejected by a unique organization/project/digest index.
- This is a bounded synchronous ingestion foundation, not a production-scale asynchronous pipeline. Object storage, job queues, parser isolation, schema-version conformance suites, package graph persistence, and external vulnerability enrichment are subsequent work.
