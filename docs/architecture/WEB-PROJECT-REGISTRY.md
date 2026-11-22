# Web project registry

The Projects navigation entry is backed by the tenant-scoped project API.

## Authentication

The workspace supports organization registration and sign-in through the existing auth endpoints. Access and refresh tokens remain in component memory only, are not written to browser storage, and refresh tokens rotate before access-token expiry. Signing out calls the API logout endpoint. The Projects and Components/Vulnerabilities workspaces currently maintain independent in-memory sessions; signing in to one does not silently authenticate the other.

Set `VITE_API_BASE_URL` at build time to the ChainProof API origin. It defaults to `http://localhost:4000`.

## Project lifecycle

- Lists up to 100 active and 100 archived projects for the authenticated organization.
- Filters locally by name, slug, and repository URL; supports active, archived, and all views.
- Creates projects with name, unique organization-scoped slug, description, HTTPS repository URL, and default branch.
- Updates project name, description, repository URL, and default branch.
- Archives projects using the existing PATCH endpoint; archive is a soft lifecycle transition and does not delete SBOMs or findings.
- Displays project timestamps and source repository metadata.

The browser never submits an organization ownership field. The API derives tenant identity from the authenticated session and scopes all project reads and writes.

## GitHub repository links

The detail panel reads existing links from the tenant/project-scoped repository-link endpoint and displays provider-owned repository metadata and link status. Creating or removing links remains an owner/admin integration-management workflow and requires a verified GitHub App installation; the Projects UI does not fabricate a linked state or trust browser-supplied repository names.

## Current boundaries

- Project list calls are bounded to 100 active and 100 archived records; server-side pagination is not implemented in this UI.
- GitHub App installation administration and repository selection are not yet surfaced as an interactive UI.
- Each workspace currently has its own in-memory auth session; reload clears it and requires sign-in again.
- The overview dashboard still contains illustrative metrics and is labeled accordingly.
