# GitHub App installation, verification and repository discovery

## Implemented

- Organization owners/admins request a GitHub App installation URL through an authenticated, tenant-scoped endpoint.
- A short-lived HMAC-signed state binds the callback to the initiating organization and user; persisted nonce consumption prevents replay.
- The callback revalidates the active user, organization and owner/admin membership, then records an installation as \`pending_verification\`.
- A backend verification endpoint authenticates to GitHub as the App using a short-lived RS256 JWT and fetches the exact installation from GitHub's App API.
- Verification checks the returned installation ID, App ID, account identity, selected-repository mode and read-only \`contents\` plus \`metadata\` permissions before activating the installation.
- Repository discovery mints a short-lived installation token in memory, lists repositories through the GitHub installation API (up to 500 per request), and discards the token without persisting or logging it.
- The installation record stores provider account identity, repository selection and granted permission metadata.

## Configuration

Configure these server-side variables from a managed secret store in production:

- \`GITHUB_APP_SLUG\`: URL slug used to construct the installation URL.
- \`GITHUB_APP_ID\`: numeric GitHub App ID.
- \`GITHUB_APP_PRIVATE_KEY\`: PEM-encoded App private key. Escaped \`\\n\` sequences are normalized to PEM newlines.

Never commit a private key to Git, expose it to the browser, or include it in logs. Prefer a cloud secret manager/KMS-backed secret reference and rotate the key through the GitHub App settings. Environment variables are a deployment interface, not a substitute for managed secret custody.

Configure the GitHub App callback URL to:

\`https://YOUR_API_HOST/api/v1/integrations/github/callback\`

The App must grant read-only **Contents** and **Metadata** permissions and use **Only select repositories**. This initial verification intentionally rejects installations configured for all repositories.

## Endpoints

- \`POST /api/v1/integrations/github/organizations/:organizationId/installations/start\` — authenticated owner/admin; returns the GitHub installation URL.
- \`GET /api/v1/integrations/github/callback?installation_id=...&state=...\` — validates and consumes state; creates a pending record only.
- \`POST /api/v1/integrations/github/organizations/:organizationId/installations/:installationId/verify\` — owner/admin; verifies the installation with GitHub's App API and activates only after all checks pass.
- \`GET /api/v1/integrations/github/organizations/:organizationId/installations/:installationId/repositories\` — owner/admin; mints an ephemeral installation token and returns the installed repository list, capped at 500 results per call.

## Security boundaries and next work

Installation tokens are short-lived and are not persisted, cached or logged in this slice. The repository discovery response is read-only; no repository is yet linked to a ChainProof project and no source contents are downloaded. Next: tenant-scoped repository selection/linking, webhook-driven installation suspension/removal, reconciliation, token refresh controls, and auditable repository sync jobs.

The callback's \`installation_id\` remains untrusted until the authenticated provider verification endpoint succeeds. A webhook payload alone must never activate an installation.
