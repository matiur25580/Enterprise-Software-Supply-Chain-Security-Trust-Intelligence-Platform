# Identity, tenant context and authorization foundation

This milestone provides security primitives and an explicitly limited access-context endpoint. It does **not** yet provide user registration, credential persistence, organization provisioning, invitations, refresh-token rotation, session revocation, MFA, or SSO.

## Passwords
Passwords are hashed with Node.js scrypt using a per-password random 16-byte salt and a 64-byte derived key. Verification uses constant-time comparison. Enforce the 12–128 character policy at the API boundary and never log passwords or hashes.

## Sessions
The current compact HMAC-SHA256 bearer token has a 15-minute default lifetime. The signing secret must be a high-entropy secret of at least 32 characters. Tokens are signed, not encrypted: claims are visible to their bearer. There is no revocation store yet, so do not use this implementation as a complete production session lifecycle.

## Tenant isolation
The active organization is taken only from the verified signed session claim. The route organization identifier must match that claim. A mismatch intentionally returns 404 to avoid disclosing another tenant's existence. Never trust an organization identifier from an arbitrary request header or body.

## Authorization
Role-to-permission mapping is centralized in `auth/roles.ts`. Route handlers must apply authentication, organization scope, then permission checks. Add resource-level ownership checks before exposing individual project, finding, or evidence records.

## Next required controls
Persist users, organizations and memberships in MongoDB; enforce unique normalized email and tenant-scoped indexes; add hashed opaque refresh tokens with rotation/reuse detection and revocation; implement login/logout/invitation flows, audit events, MFA/SSO, rate limits, CSRF protection if cookie sessions are introduced, and integration tests for cross-tenant denial.
