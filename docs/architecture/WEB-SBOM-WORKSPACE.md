# Web SBOM and vulnerability workspace

The Components and Vulnerabilities navigation entries now use the authenticated ChainProof API instead of the previous placeholder module screen.

## Authentication

The workspace signs in through `POST /api/v1/auth/login` using email, password, and organization slug. Access and refresh tokens remain in React memory only and are cleared on sign-out or page reload. The access token is sent as a bearer token to API requests. The API base defaults to `http://localhost:4000`; deployments should set `VITE_API_BASE_URL` at build time.

The UI does not store credentials or tokens in localStorage/sessionStorage. Access tokens currently expire after the API's 15-minute TTL; the user must sign in again after expiry or reload. Automatic refresh and a secure same-site cookie/BFF session are future work.

## SBOM inventory

The Components workspace loads active projects and their SBOM inventories. It accepts JSON files and submits the parsed CycloneDX 1.x or SPDX 2.x document to the tenant-scoped SBOM endpoint. Duplicate documents, invalid JSON, unsupported SBOM formats, authorization failures, and API errors are displayed as actionable errors. It shows normalized inventory metadata and SHA-256 digest prefixes.

## Vulnerability intelligence

Users select an ingested SBOM and trigger the OSV scan endpoint. The UI displays queried package count, skipped package count, advisory match count, and the project's open findings. Finding rows show component, advisory identifier, severity, CVSS score when available, fixed versions, and recommended action.

All project and finding data is loaded from authenticated API responses. The dashboard's existing overview metrics remain explicitly labeled illustrative demo data; the new Components and Vulnerabilities views are live API-backed data.

## Current boundaries

- The user must already have an organization account and at least one active project.
- Access token refresh is not automatic yet; a 401 requires signing in again.
- There is no browser-side project creation, registration, pagination, filtering, or finding acceptance workflow yet.
- The upload uses a browser JSON parse/stringify round trip and the API's 2 MiB request limit.
- No claim is made that an empty OSV result proves a package is secure.
