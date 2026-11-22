# GitHub App connection workspace

The Projects workspace exposes the tenant-scoped GitHub App installation and repository-linking lifecycle.

## Admin workflow

1. Sign in as an organization owner or administrator.
2. Open Projects and select an active project.
3. Choose **Install GitHub App**. ChainProof creates a short-lived signed state and redirects to the configured GitHub App installation URL.
4. Complete the GitHub-hosted installation flow. The callback records a pending installation; it does not grant repository access.
5. Return to ChainProof and refresh installations. Verify the pending installation against GitHub.
6. Select the active verified installation, discover available repositories, and link a selected repository to the active project.

## API additions and existing routes

- `GET /api/v1/integrations/github/organizations/:organizationId/installations` lists only the authenticated tenant's installation metadata.
- `POST /api/v1/integrations/github/organizations/:organizationId/installations/start` creates the signed installation state and returns the GitHub install URL.
- `GET /api/v1/integrations/github/callback` consumes the one-time state and records a pending installation.
- `POST /api/v1/integrations/github/organizations/:organizationId/installations/:installationId/verify` verifies provider identity, App ID, installation ID and allowed permissions.
- `GET /api/v1/integrations/github/organizations/:organizationId/installations/:installationId/repositories` discovers repositories using an ephemeral, narrowly scoped installation token.
- `POST /api/v1/integrations/github/organizations/:organizationId/projects/:projectId/repositories` links a repository by installation ID and provider repository ID.
- `DELETE /api/v1/integrations/github/organizations/:organizationId/projects/:projectId/repositories/:repositoryId` soft-unlinks a repository.

## Security boundaries

- The browser never supplies repository name, owner, URL, visibility, default branch or tenant ownership as authoritative metadata.
- API authorization and tenant scope are checked for each operation.
- Only active verified installations are eligible for repository discovery and linking.
- Provider inventory is fetched server-side; a repository ID must be present in that installation's current inventory.
- The GitHub App is restricted to selected repositories and read-only Contents and Metadata permissions.
- Installation access tokens are short-lived and remain in server memory; they are not persisted or logged.
- Repository source contents are not fetched, cloned, or executed by this workflow.
- GitHub App slug, App ID, private key and webhook secret must be configured server-side. Never put them in frontend environment variables.

## Operational note

The callback currently returns a JSON confirmation response. After completing GitHub's installation flow, the administrator returns to the Projects workspace and refreshes the installation inventory. This is intentional for this implementation slice; a polished product redirect/deep-link flow can be added separately.


## Repository metadata synchronization

The Projects workspace offers **Sync now** for an active linked repository. The API mints an ephemeral read-only installation token, fetches the repository metadata and default-branch commit from GitHub, validates the provider repository ID and full name against the stored link, and persists the last synchronization time, commit SHA, commit timestamp, default branch, visibility, and sync status. It rechecks installation activity before committing the snapshot and writes an audit event. Failures are recorded as a bounded error string and a failed sync status.

Endpoint: `POST /api/v1/integrations/github/organizations/:organizationId/projects/:projectId/repositories/:repositoryId/sync` (requires `integrations:manage`).

This is a bounded on-demand metadata synchronization, not yet a background job. It does not fetch repository file contents, discover or ingest committed SBOM files, enqueue vulnerability scans, or process push webhooks asynchronously. Those are separate follow-on capabilities; no source code is cloned or executed by this endpoint.
