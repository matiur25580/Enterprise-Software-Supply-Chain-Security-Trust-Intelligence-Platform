# Identity, tenant context and authorization

The API persists identity and session state in MongoDB. This is an early production-oriented foundation, not a complete identity provider: MFA, SSO, email verification, password reset, invitations, and device management remain out of scope.

## Data model and indexes

- `User`: normalized unique email, scrypt password hash excluded from ordinary queries, active/disabled status.
- `Organization`: unique normalized slug and active/suspended status.
- `Membership`: organization/user pair has a unique compound index; membership status and role are authoritative for access.
- `IdentitySession`: opaque refresh-token SHA-256 hashes only, bounded absolute expiry, revocation state, and previous-token hash history for replay detection.
- `AuditEvent`: append-oriented events with organization timeline and actor timeline indexes.
- `Project`: tenant-owned project metadata with unique organization/slug and tenant/status indexes.

Application identifiers are UUIDs; MongoDB internal ObjectIds are not accepted as tenant selectors. Never trust organization IDs from request bodies or headers.

## Database requirements

Registration uses MongoDB transactions, so MongoDB must run as a replica set (a single-node replica set is sufficient locally). Automatic index creation is disabled in production. Run `pnpm --filter @chainproof/api db:indexes` as a controlled deployment migration to create identity and project indexes.

## Authentication lifecycle

- `POST /api/v1/auth/register`: creates a user and organization; the first membership is `org_owner`.
- `POST /api/v1/auth/login`: requires email, password, and organization slug; generic credential errors avoid disclosing which check failed.
- `POST /api/v1/auth/refresh`: rotates a 384-bit opaque refresh token. Only SHA-256 hashes are stored. Reuse of a consumed token revokes the session family.
- `POST /api/v1/auth/logout`: requires a live access token and revokes its persisted session.
- Every authenticated request checks the persisted session, active user, active organization, and active membership. Effective role is loaded from membership state.

Authentication routes share a process-local IP-based rate limit. Before horizontally scaling API instances, replace the in-memory limiter store with a shared Redis-backed store. Request bodies use strict Zod schemas; error responses do not expose database or cryptographic internals.

## Tenant and authorization rules

Authenticated membership is the source of tenant and role context. Organization path IDs must match the authenticated organization; mismatches return 404. Every project list/item query includes the authenticated organization ID in its MongoDB filter. Item operations also include the project UUID. Strict request schemas reject client-supplied organization and ownership fields.

Project routes:
- `GET /api/v1/organizations/:organizationId/projects` — requires `projects:read`.
- `POST /api/v1/organizations/:organizationId/projects` — requires `projects:write`.
- `GET /api/v1/organizations/:organizationId/projects/:projectId` — requires `projects:read`.
- `PATCH /api/v1/organizations/:organizationId/projects/:projectId` — requires `projects:write`.

Repository URLs are metadata only. The API does not fetch or execute repository content. Provider installation, webhook signature verification, and source-control synchronization are separate future work. See [Project registry architecture](../../../docs/architecture/PROJECT-REGISTRY.md).

## Operational controls and limitations

- Use HTTPS and a secrets manager. Refresh tokens are returned once and must be stored in protected client storage, never logs or browser local storage.
- Refresh expiry is absolute (30 days). MongoDB TTL cleanup is asynchronous; authorization checks explicit expiry.
- Consumed refresh-token hashes remain in the session document for replay detection until expiry.
- Audit writes are awaited for identity and project create/update operations.
- Configure MongoDB backups, encryption at rest, network restrictions, alerting, and index migrations before production.
- Add MFA, SSO, email verification, password recovery, account lockout, and invitation governance before broad enterprise rollout.

## GitHub App and repository links

GitHub App installation callbacks remain pending until verified against GitHub's App API. Verification requires the configured App ID, a valid RS256 App JWT, selected-repository mode, and read-only Contents/Metadata permissions. Installation tokens are ephemeral and scoped to those read permissions.

- `GET /api/v1/integrations/github/organizations/:organizationId/projects/:projectId/repositories` — list a project's repository links; requires `projects:read`.
- `POST /api/v1/integrations/github/organizations/:organizationId/projects/:projectId/repositories` — link a repository using only `installationId` and `repositoryId`; requires `integrations:manage`. Repository metadata is fetched from the verified provider inventory, not trusted from the client.
- `DELETE /api/v1/integrations/github/organizations/:organizationId/projects/:projectId/repositories/:repositoryId` — soft-unlink with audit event; requires `integrations:manage`.

Repository IDs are unique within an organization and cannot be linked to multiple projects in that organization. Signed GitHub installation suspend, unsuspend and delete events update installation and repository-link status. No source code is fetched or executed in this milestone. See [GitHub App installation and repository linking](../../../docs/architecture/GITHUB-APP-INSTALLATION.md).
