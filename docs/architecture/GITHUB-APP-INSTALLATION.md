# GitHub App installation and tenant connection

## What is implemented

- Organization owners/admins can request a GitHub App installation URL through an authenticated, tenant-scoped endpoint.
- A short-lived HMAC-signed state binds the callback to the initiating organization and user.
- State nonces are persisted and consumed once, preventing callback replay.
- The callback re-checks the user, organization and active owner/admin membership before recording the installation.
- Installation records are created as `pending_verification`; they cannot be used for repository access yet.
- Installation IDs are globally unique and organizations can link only one installation in this initial model.

## Configuration

Set `GITHUB_APP_SLUG` to the GitHub App's URL slug. Configure the GitHub App setup URL/callback to point to:

`https://YOUR_API_HOST/api/v1/integrations/github/callback`

The existing `AUTH_SESSION_SECRET` signs short-lived state. Use a unique high-entropy secret in production. No GitHub App private key, client secret, user token or installation token is stored by this slice.

## Endpoints

- `POST /api/v1/integrations/github/organizations/:organizationId/installations/start` — authenticated and tenant-scoped; requires `integrations:manage` (organization owner/admin).
- `GET /api/v1/integrations/github/callback?installation_id=...&state=...` — verifies signed state, consumes its nonce once, revalidates the actor's current membership, then records a pending installation.

## Important security boundary

A callback's `installation_id` is untrusted input. This flow does **not** claim that GitHub has cryptographically verified the installation. Before enabling repository discovery, a backend worker must authenticate as the GitHub App using a private key held in a managed secret store, call GitHub's installation API, verify the installation account and granted permissions, and only then transition the record to `active`. Never authorize repository access based only on this callback or a webhook payload.

Next: managed private-key custody, GitHub App JWT generation, installation API verification, least-privilege repository permissions, repository selection/allowlisting, and encrypted installation-token caching.
