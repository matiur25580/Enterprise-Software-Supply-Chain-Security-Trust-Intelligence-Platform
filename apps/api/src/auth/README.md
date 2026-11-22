# Identity, tenant context and authorization

The API now persists identity and session state in MongoDB. The implementation is an early production-oriented foundation, not a complete identity provider: MFA, SSO, email verification, password reset, invitation workflows, and device management remain out of scope.

## Data model and indexes

- `User`: normalized unique email, scrypt password hash excluded from ordinary queries, active/disabled status.
- `Organization`: unique normalized slug and active/suspended status.
- `Membership`: organization/user pair has a unique compound index; membership status and role are authoritative for access.
- `IdentitySession`: opaque refresh-token SHA-256 hashes only, bounded absolute expiry, revocation state, and previous-token hash history for replay detection.
- `AuditEvent`: append-oriented events with organization timeline and actor timeline indexes.

Application identifiers are UUIDs; MongoDB's internal ObjectIds are not accepted as tenant selectors. Never trust organization IDs from request bodies or headers.

## Database requirements

Set `MONGODB_URI` to a private MongoDB deployment. Organization registration uses a MongoDB transaction so user, organization, owner membership, initial session, and audit event commit or roll back together. The MongoDB deployment must therefore be a replica set (a single-node replica set is sufficient for local development). Production index creation should be managed as a deployment migration; automatic index creation is disabled in production.

Example local URI: `mongodb://127.0.0.1:27017/chainproof?replicaSet=rs0`.

## Authentication lifecycle

- `POST /api/v1/auth/register`: creates a user and organization; the first membership is `org_owner`.
- `POST /api/v1/auth/login`: requires email, password, and organization slug; generic credential errors avoid disclosing which check failed.
- `POST /api/v1/auth/refresh`: rotates a 384-bit opaque refresh token. Only SHA-256 hashes are stored. Reuse of a consumed token revokes the session family.
- `POST /api/v1/auth/logout`: requires a live access token and revokes its persisted session.
- Access tokens are short-lived HMAC-SHA256 signed tokens. Every authenticated request also checks the persisted session, active user, active organization, and active membership. Role claims are refreshed from the membership record rather than trusted from the bearer token.

Authentication routes share an IP-based rate limit. Request bodies are strict Zod schemas. Error responses never return database or cryptographic internals.

## Tenant and authorization rules

The authenticated membership is the source of tenant and role context. Route organization IDs are only accepted when they exactly match the authenticated organization; mismatches return 404. Protected data repositories must still include the authenticated organization ID in every database filter and must enforce resource-level authorization. Never query tenant resources by a client-supplied organization ID alone.

## Operational controls and limitations

- Use HTTPS and a secrets manager. The refresh token is returned once in the response body; clients must store it in protected platform storage and never in logs or browser local storage.
- The 30-day refresh-session expiry is absolute, not sliding. MongoDB TTL cleanup is asynchronous; authorization always checks the explicit expiry timestamp.
- Consumed refresh-token hashes remain in the session document for replay detection until expiry.
- Audit writes are awaited for successful lifecycle operations and replay detection.
- Configure MongoDB backups, encryption at rest, network restrictions, alerting, and index migrations before production.
- Add MFA, SSO, email verification, password recovery, account lockout policy, and invitation governance before broad enterprise rollout.
