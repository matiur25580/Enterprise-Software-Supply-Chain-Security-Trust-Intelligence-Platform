# VEX risk acceptance

ChainProof supports tenant-scoped, time-limited risk acceptance for a specific advisory and package URL found in a completed SBOM vulnerability scan.

## Record an acceptance

`POST /api/vex/exceptions` (platform-admin or security-analyst)

```json
{
  "sbomId": "64b000000000000000000001",
  "scanId": "64b000000000000000000002",
  "advisoryId": "GHSA-example",
  "purl": "pkg:npm/example@1.2.3",
  "rationale": "The affected code path is not reachable in this deployment; evidence is documented in the security review.",
  "compensatingControls": "Runtime egress policy and application-layer request validation are enabled.",
  "expiresAt": "2027-01-15T00:00:00.000Z"
}
```

The API verifies that the SBOM and completed scan belong to the authenticated tenant and that the exact advisory/PURL pair occurs in that scan. Expiry must be in the future and within 90 days. The decision records the accepting user, timestamp, rationale and compensating controls. A risk acceptance is not a claim that the vulnerability is fixed or absent.

## Review and revoke

- `GET /api/vex/exceptions` lists tenant-scoped acceptances and derives an effective `expired` state after expiry.
- `POST /api/vex/exceptions/:id/revoke` revokes an active acceptance. Body: `{"reason":"The compensating control is no longer deployed."}`

Expired or revoked acceptances are not active exceptions. VEX records remain attached as audit evidence. During release-policy evaluation, an active acceptance for the exact advisory and PURL downgrades that finding's vulnerability checks to an explainable warning; it never marks the finding fixed or removes it. Expired or revoked records have no effect. Provenance failures and unrelated findings continue to enforce their normal policy checks.
