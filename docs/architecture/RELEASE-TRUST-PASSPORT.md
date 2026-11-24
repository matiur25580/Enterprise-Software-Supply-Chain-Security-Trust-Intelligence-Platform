# Release Trust Passport

## Purpose

A Release Trust Passport is a portable, signed evidence envelope binding an artifact SHA-256 digest to a tenant-owned SBOM record, the latest available OSV scan snapshot, a matching verified SLSA provenance record when present, and a persisted policy evaluation.

The passport is an evidence artifact. It is not a release authorization token, regulatory attestation, or proof that every supply-chain risk has been evaluated. A passport can record `pass`, `warn`, or `block`; consumers must review the policy version and evidence.

## Signature format

- Schema: `chainproof.release-trust-passport/v1`
- Signature algorithm: Ed25519
- Message: UTF-8 canonical JSON with recursively sorted object keys over `algorithm`, `keyId`, and `payload`
- Key ID: SHA-256 fingerprint of the DER-encoded SubjectPublicKeyInfo
- Envelope: algorithm, key ID, PEM public key, payload and base64 signature

The public key is embedded so the envelope can be verified offline. The key fingerprint must be distributed through a trusted channel; a self-contained public key proves integrity, not the identity of its publisher.

## Signing-key operations

Generate a persistent development key:

```bash
openssl genpkey -algorithm ED25519 -out release-passport-private.pem
chmod 600 release-passport-private.pem
export RELEASE_PASSPORT_PRIVATE_KEY="$(cat release-passport-private.pem)"
```

Do not commit the private key or place it in logs, shell history or screenshots. In production, inject it from a secret manager and plan rotation/retention of trusted public-key fingerprints. If the key is not configured, passport issuance returns HTTP 503. Existing passports remain verifiable using their embedded public key and fingerprint.

## API

- `POST /api/policy/release-passports` — body: `{"evaluationId":"<policy-evaluation-object-id>"}`; issues and persists a signed passport.
- `GET /api/policy/release-passports` — tenant-scoped passport inventory.
- `GET /api/policy/release-passports/:passportId` — returns the passport and a fresh cryptographic verification result.

All endpoints require authentication and enforce role permissions. Passport lookup and evidence selection are tenant-scoped. The passport contains no raw SBOM document, artifact bytes, credentials or signing private key.

## Offline verification and trust decisions

Save the returned response as `release-passport.json`. A basic offline check validates the signature and embedded key fingerprint:

```bash
npm run passport:verify -- --file ./release-passport.json
```

Cryptographic validity alone does not establish publisher trust. For a trust decision, distribute an authenticated trust-store JSON file to the verifier. The file uses this format:

```json
{
  "schemaVersion": "chainproof.release-passport-trust-store/v1",
  "keys": [
    { "keyId": "<64-character-sha256-fingerprint>", "status": "active" },
    { "keyId": "<previous-fingerprint>", "status": "retired" },
    { "keyId": "<compromised-fingerprint>", "status": "revoked" }
  ]
}
```

Then require a registered, non-revoked signer:

```bash
npm run passport:verify -- --file ./release-passport.json \\
  --trust-store ./release-passport-trust-store.json --require-trusted
```

The verifier accepts `active` and `retired` keys, rejects `revoked` and `unregistered` keys, and reports a separate trust status. A retired key remains valid for historical passports; it must not be used for new issuance. `--require-trusted` fails closed if the trust store is missing. Keep the trust store itself integrity-protected and distribute it through an authenticated channel; do not trust a registry file supplied alongside an untrusted passport.

Exit codes: 0 = signature valid and any requested trust requirement satisfied; 1 = invalid command/file/JSON/trust-store format; 2 = invalid signature or tampered payload; 3 = signer is revoked/unregistered or required trust is not established. Without `--trust-store`, the CLI reports `trustStatus: "not_checked"` and only establishes cryptographic integrity.

## Operational controls and limitations

- Keep the private key in a secret manager; use a separate key per environment.
- Distribute signer fingerprints and statuses through an authenticated channel; preserve retired public-key fingerprints for historical verification.
- Restrict passport issuance to authenticated security roles; reads are tenant-scoped and auditor-readable.
- The current passport includes up to 100 advisory summaries to bound payload size.
- It references a policy evaluation snapshot and the latest available scan/provenance metadata; it does not re-run upstream scans.
- It is not a DSSE or in-toto attestation and does not replace native Sigstore bundles or SLSA provenance.
