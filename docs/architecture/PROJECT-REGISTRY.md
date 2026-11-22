# Project registry and tenant boundaries

The project registry is the first application-domain resource built on the persisted identity foundation.

## API

All routes require a live bearer session, an active persisted membership, a matching organization path, and the appropriate permission:

- `GET /api/v1/organizations/:organizationId/projects` — list projects in the authenticated organization.
- `POST /api/v1/organizations/:organizationId/projects` — create a project.
- `GET /api/v1/organizations/:organizationId/projects/:projectId` — read one project.
- `PATCH /api/v1/organizations/:organizationId/projects/:projectId` — update project metadata or archive it.

The organization ID is derived from the authenticated session and active membership. The request body schema is strict and does not accept tenant or ownership fields. Every project query includes both the authenticated organization ID and, for item operations, the requested project ID. A project ID from another tenant therefore resolves as not found.

## Data and security controls

- Project identifiers are UUIDs; slugs are unique within an organization.
- Repository URLs must use HTTPS and cannot include embedded credentials.
- Project creation and updates emit organization-scoped audit events.
- Reads require `projects:read`; writes require `projects:write`.
- List results are bounded to 100 documents per request.
- The model has compound tenant/status and tenant/slug indexes.

This registry does not yet connect to source-control providers, fetch repository contents, install webhooks, or ingest SBOMs. Those integrations must use scoped credentials, explicit installation authorization, bounded asynchronous jobs, and verified webhook signatures. A repository URL is metadata only and is never fetched or executed by this API.


## SBOM inventory extension

Projects can now accept bounded JSON CycloneDX 1.x and SPDX 2.x documents through the project-scoped SBOM API. Uploads are tenant-scoped, deduplicated by SHA-256, normalized to component metadata, and audited. The parser retains package identifiers and license metadata but does not retain the original SBOM document or fetch/execute source. See [SBOM ingestion foundation](SBOM-INGESTION.md).
