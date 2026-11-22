# Cryptographic release attestation verification

ChainProof accepts a DSSE-wrapped in-toto Statement for a release and verifies it against operator-configured Ed25519 trust roots before marking the release eligible.

## Trust-root configuration

Set `CHAINPROOF_ATTESTATION_TRUSTED_KEYS` in the API deployment secret manager to a JSON object keyed by stable key IDs:

```json
{
  "ci-prod-2026": {
    "algorithm": "ed25519",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
  }
}
```

Only Ed25519 SPKI PEM public keys are accepted. Configure private signing keys only in the trusted CI/build system; ChainProof receives public keys only. Rotate keys by adding the new key ID before changing the signer, retaining the old public key while previously issued releases need to be verified. Remove compromised keys from the trust map to prevent future releases from relying on them. Existing release records retain the verification result observed at creation time.

## Attestation format

The release create request may include a DSSE envelope with:
- `payloadType`: `application/vnd.in-toto+json`
- `payload`: base64-encoded in-toto Statement v1 JSON
- `signatures`: one to five signatures, each with `keyid` and base64 `sig`

The statement predicate type must be `https://chainproof.dev/attestations/release-provenance/v1`. Its `subject` must include the release artifact's SHA-256 digest. Its predicate must contain exact `sourceRepository`, `sourceCommitSha`, `builderIdentity`, and `buildRunUrl` claims matching the release request.

The signer signs the DSSE pre-authentication encoding (PAE), not raw JSON:

`DSSEv1 <payloadType byte length> <payloadType> <payload byte length> <payload>`

All lengths are UTF-8 byte lengths. The server verifies the signature using the public key selected by `keyid`.

## Release gate behavior

A release is eligible only when:
- at least one signature verifies under a configured trusted Ed25519 key;
- the signed artifact digest matches the release artifact digest;
- signed provenance claims match the submitted source repository, commit, builder identity, and build run URL;
- provenance fields are complete;
- there are no open critical or high findings in the associated SBOM.

Missing, invalid, mismatched, or untrusted attestations are persisted with explicit verification status and block eligibility. The release assessment is still recorded for audit and triage; blocked means it must not be promoted.

The API stores the attestation envelope digest, selected key ID, verification time, status, and reasons. It does not retain the entire DSSE envelope. Audit metadata records the key ID and envelope digest.

## Security boundaries

- Trust roots are operator-controlled deployment configuration, not caller-supplied keys.
- The current supported signing algorithm is Ed25519 only.
- The verifier bounds payload size, signature count, and key-map size.
- The verifier validates the DSSE PAE signature, in-toto statement type, predicate type, artifact subject, and exact provenance claims.
- The verifier does not contact the build provider, validate that a workflow URL exists, or establish the real-world identity of a builder beyond the trust root and signed claim.
- The SBOM vulnerability summary is a point-in-time snapshot; it must be refreshed before a later promotion decision.
- Verification is performed at release creation. Key revocation or later policy changes do not automatically re-evaluate historical releases; a future re-verification workflow is needed for continuous trust.

This is a ChainProof-specific in-toto predicate profile, not a claim of complete SLSA conformance or Sigstore bundle verification.
