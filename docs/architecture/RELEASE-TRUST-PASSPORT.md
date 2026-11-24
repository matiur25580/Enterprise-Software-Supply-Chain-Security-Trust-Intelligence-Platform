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

## Offline verification

Save the returned response as `release-passport.json` and run:

```bash
npm run passport:verify -- --file ./release-passport.json
```

Exit codes: 0 = valid signature and fingerprint; 1 = invalid command/file/JSON; 2 = invalid signature or tampered payload. Offline verification checks cryptographic integrity and key consistency. It does not decide whether the key is trusted or whether the policy is adequate.

## Operational controls and limitations

- Keep the private key in a secret manager; use a separate key per environment.
- Distribute the key fingerprint through an authenticated channel and maintain an explicit trusted-key registry in downstream consumers.
- Preserve old public-key fingerprints for verification after key rotation.
- Restrict passport issuance to authenticated security roles; reads are tenant-scoped and auditor-readable.
- The current passport includes up to 100 advisory summaries to bound payload size.
- It references a policy evaluation snapshot and the latest available scan/provenance metadata; it does not re-run upstream scans.
- It is not a DSSE or in-toto attestation and does not replace native Sigstore bundles or SLSA provenance.
