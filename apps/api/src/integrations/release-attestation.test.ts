import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  DSSE_PAYLOAD_TYPE, RELEASE_PROVENANCE_PREDICATE, verifyReleaseAttestation,
  type DsseEnvelope, type ExpectedReleaseProvenance, type TrustedAttestationKey
} from "./release-attestation.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const expected: ExpectedReleaseProvenance = {
  artifactSha256: "a".repeat(64),
  sourceRepository: "https://github.com/acme/service",
  sourceCommitSha: "b".repeat(40),
  builderIdentity: "github-actions/acme/service",
  buildRunUrl: "https://github.com/acme/service/actions/runs/42"
};
const trustedKeys: Record<string, TrustedAttestationKey> = {
  "ci-prod-2026": { publicKeyPem, algorithm: "ed25519" }
};
function envelope(overrides: Record<string, unknown> = {}): DsseEnvelope {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "service.tar.gz", digest: { sha256: expected.artifactSha256 } }],
    predicateType: RELEASE_PROVENANCE_PREDICATE,
    predicate: {
      sourceRepository: expected.sourceRepository,
      sourceCommitSha: expected.sourceCommitSha,
      builderIdentity: expected.builderIdentity,
      buildRunUrl: expected.buildRunUrl
    },
    ...overrides
  };
  const payload = Buffer.from(JSON.stringify(statement));
  const payloadType = DSSE_PAYLOAD_TYPE;
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `),
    payload
  ]);
  return {
    payloadType,
    payload: payload.toString("base64"),
    signatures: [{ keyid: "ci-prod-2026", sig: sign(null, pae, privateKey).toString("base64") }]
  };
}

test("accepts a correctly signed DSSE attestation from a configured Ed25519 trust root", () => {
  assert.equal(verifyReleaseAttestation(envelope(), expected, trustedKeys).status, "verified");
});
test("rejects a valid signature whose subject artifact digest differs", () => {
  assert.equal(verifyReleaseAttestation(envelope({
    subject: [{ name: "other.tar.gz", digest: { sha256: "c".repeat(64) } }]
  }), expected, trustedKeys).status, "failed");
});
test("rejects modified signed payload bytes", () => {
  const value = envelope();
  value.payload = Buffer.from(JSON.stringify({
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "service.tar.gz", digest: { sha256: expected.artifactSha256 } }],
    predicateType: RELEASE_PROVENANCE_PREDICATE,
    predicate: { ...expected, sourceCommitSha: "d".repeat(40) }
  })).toString("base64");
  assert.equal(verifyReleaseAttestation(value, expected, trustedKeys).status, "failed");
});
test("does not trust an otherwise valid signature from an unknown key", () => {
  assert.equal(verifyReleaseAttestation(envelope(), expected, {}).status, "untrusted_key");
});
test("blocks absent and unsupported attestations", () => {
  assert.equal(verifyReleaseAttestation(undefined, expected, trustedKeys).status, "not_provided");
  assert.equal(verifyReleaseAttestation({ ...envelope(), payloadType: "application/json" }, expected, trustedKeys).status, "failed");
});
test("rejects signed provenance claims that do not match the submitted release", () => {
  const value = envelope();
  const statement = JSON.parse(Buffer.from(value.payload, "base64").toString("utf8"));
  statement.predicate.sourceRepository = "https://github.com/attacker/repo";
  value.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  assert.equal(verifyReleaseAttestation(value, expected, trustedKeys).status, "failed");
});
