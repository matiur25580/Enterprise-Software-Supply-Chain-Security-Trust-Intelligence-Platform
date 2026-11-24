# Release Passport Signer Lifecycle

ChainProof maintains a tenant-scoped trust registry for Ed25519 Release Trust Passport signers. The private key remains server-side in `RELEASE_PASSPORT_PRIVATE_KEY`; the API accepts neither private-key material nor arbitrary public keys from clients.

## Generate and configure a replacement key

Generate a fresh key outside the repository and inject it through your secret manager:

```bash
openssl genpkey -algorithm ED25519 -out release-passport-private-next.pem
chmod 600 release-passport-private-next.pem
# Update RELEASE_PASSPORT_PRIVATE_KEY in the deployment secret manager.
```

After deploying the new secret, an authenticated platform administrator activates its public-key fingerprint:

```bash
curl -X POST "$CHAINPROOF_API/api/policy/release-signers/rotate" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"expectedCurrentKeyId":"<currently-active-64-char-key-id>"}'
```

The expected-current fingerprint provides optimistic concurrency protection. The previous active signer is moved to `retired`; it is retained for historical passport verification and is not deleted. If no current signer exists, omit `expectedCurrentKeyId`.

## Inventory and revocation

```bash
curl "$CHAINPROOF_API/api/policy/release-signers" -H "Authorization: Bearer $TOKEN"

curl -X POST "$CHAINPROOF_API/api/policy/release-signers/revoke" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"keyId":"<64-char-key-id>","reason":"Key material was exposed; incident INC-1234"}'
```

Only `platform-admin` can rotate or revoke. Authenticated developers, security analysts and auditors can view the tenant's signer inventory. Revocation is terminal: a revoked key cannot be reactivated through the rotation endpoint. Revoke a compromised key immediately and rotate to a fresh secret.

## States and verification semantics

- `active`: current trusted signer selected for new issuance by operational policy.
- `retired`: no longer selected for new issuance; retained to support historical signature verification.
- `revoked`: compromised or otherwise distrusted; consumers must reject signatures made by this key even if the cryptographic signature verifies.

The registry is an auditable trust source; offline signature verification alone proves integrity, not publisher trust. Consumers must compare the passport's `keyId` against an authenticated signer inventory and reject `revoked` keys. This registry does not rotate deployment secrets automatically and does not export private keys.

## API

- `GET /api/policy/release-signers` — tenant-scoped inventory.
- `POST /api/policy/release-signers/rotate` — activate the public key derived from the server-configured private key; optional `expectedCurrentKeyId`.
- `POST /api/policy/release-signers/revoke` — revoke a key with a mandatory audit reason.
