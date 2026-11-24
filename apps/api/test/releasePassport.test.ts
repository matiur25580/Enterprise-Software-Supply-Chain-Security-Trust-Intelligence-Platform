import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createSignedReleasePassport, verifySignedReleasePassport, type ReleasePassportPayload } from "../src/services/releasePassport";

const { privateKey } = generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const payload: ReleasePassportPayload = {
  schemaVersion: "chainproof.release-trust-passport/v1",
  passportId: "b5d0c6e5-0d8e-4f45-9d40-8cfc4f1a0011",
  issuedAt: "2026-11-24T00:00:00.000Z",
  artifact: { sha256: "a".repeat(64) },
  sbom: { recordId: "64b000000000000000000001", format: "CycloneDX", componentCount: 12 },
  vulnerability: { source: "OSV", scannedAt: "2026-11-24T00:00:00.000Z", scannedPackages: 12, vulnerablePackages: 0, findingCount: 0, advisories: [] },
  provenance: { verificationType: "sigstore-slsa-provenance", verifiedAt: "2026-11-24T00:00:00.000Z", builderId: "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main" },
  policy: { evaluationId: "64b000000000000000000002", version: "chainproof-release-v1", outcome: "pass", riskScore: 0, evaluatedAt: "2026-11-24T00:00:00.000Z", checks: [{ id: "scan", status: "pass", message: "Recent scan present" }] }
};

describe("signed Release Trust Passport", () => {
  it("signs and verifies a portable Ed25519 evidence envelope", () => {
    const passport = createSignedReleasePassport(payload, privatePem);
    expect(passport.algorithm).toBe("Ed25519");
    expect(passport.keyId).toMatch(/^[a-f0-9]{64}$/);
    expect(verifySignedReleasePassport(passport)).toBe(true);
  });
  it("detects tampering with policy evidence", () => {
    const passport = createSignedReleasePassport(payload, privatePem);
    const tampered = { ...passport, payload: { ...passport.payload, policy: { ...passport.payload.policy, outcome: "pass" as const, riskScore: 100 } } };
    expect(verifySignedReleasePassport(tampered)).toBe(false);
  });
  it("rejects a non-Ed25519 signing key", () => {
    const { privateKey: rsaKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => createSignedReleasePassport(payload, rsaKey.export({ type: "pkcs8", format: "pem" }).toString())).toThrow(/Ed25519/);
  });
});
