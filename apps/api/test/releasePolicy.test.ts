import { describe, expect, it } from "vitest";
import { evaluateReleasePolicy } from "../src/services/releasePolicy";

const digest = "a".repeat(64);
const provenance = { artifactDigest: digest, status: "verified", verificationType: "sigstore-slsa-provenance" };
const cleanScan = { scannedAt: "2026-11-24T00:00:00.000Z", findings: [] };

describe("deterministic release policy", () => {
  it("passes only with a recent scan, no findings and matching verified SLSA provenance", () => {
    const result = evaluateReleasePolicy({ scan: cleanScan, provenance, artifactDigest: digest, now: new Date("2026-11-24T01:00:00Z") });
    expect(result.outcome).toBe("pass");
    expect(result.riskScore).toBe(0);
  });
  it("blocks release when a CISA KEV finding is present", () => {
    const result = evaluateReleasePolicy({ scan: { ...cleanScan, findings: [{ id: "CVE-SYNTHETIC", isKnownExploited: true }] }, provenance, artifactDigest: digest });
    expect(result.outcome).toBe("block");
    expect(result.checks.some((check) => check.id === "cisa-kev" && check.status === "block")).toBe(true);
  });
  it("blocks critical CVSS and high EPSS", () => {
    const result = evaluateReleasePolicy({ scan: { ...cleanScan, findings: [{ id: "CVE-1", cvssScore: 9.8 }, { id: "CVE-2", epssScore: 0.91 }] }, provenance, artifactDigest: digest });
    expect(result.outcome).toBe("block");
    expect(result.riskScore).toBe(95);
  });
  it("warns for high CVSS or elevated EPSS below the block threshold", () => {
    const result = evaluateReleasePolicy({ scan: { ...cleanScan, findings: [{ id: "CVE-1", cvssScore: 7.5 }, { id: "CVE-2", epssScore: 0.6 }] }, provenance, artifactDigest: digest });
    expect(result.outcome).toBe("warn");
  });
  it("blocks when provenance is missing or the artifact digest does not match", () => {
    const missing = evaluateReleasePolicy({ scan: cleanScan, provenance: null, artifactDigest: digest });
    const mismatch = evaluateReleasePolicy({ scan: cleanScan, provenance: { ...provenance, artifactDigest: "b".repeat(64) }, artifactDigest: digest });
    expect(missing.outcome).toBe("block");
    expect(mismatch.outcome).toBe("block");
  });
  it("warns when the latest scan is older than 30 days", () => {
    const result = evaluateReleasePolicy({ scan: { scannedAt: "2026-10-01T00:00:00Z", findings: [] }, provenance, artifactDigest: digest, now: new Date("2026-11-24T00:00:00Z") });
    expect(result.outcome).toBe("warn");
    expect(result.checks.find((check) => check.id === "scan-freshness")?.status).toBe("warn");
  });

  it("downgrades only an exact active VEX-accepted finding to an explainable warning", () => {
    const result = evaluateReleasePolicy({
      scan: { ...cleanScan, findings: [{ id: "CVE-ACCEPTED", purl: "pkg:npm/example@1.0.0", isKnownExploited: true, cvssScore: 9.8 }] },
      provenance, artifactDigest: digest, now: new Date("2026-11-24T12:00:00Z"),
      riskAcceptances: [{
        exceptionId: "exception-1", advisoryId: "CVE-ACCEPTED", purl: "pkg:npm/example@1.0.0",
        rationale: "Affected code path is unreachable in this deployment.",
        compensatingControls: "Runtime egress policy is enabled.",
        acceptedBy: "reviewer-1", acceptedAt: "2026-11-20T12:00:00Z",
        expiresAt: "2026-12-20T12:00:00Z", status: "accepted"
      }]
    });
    expect(result.outcome).toBe("warn");
    expect(result.checks.some((check) => check.id === "vex-risk-acceptance" && check.status === "warn")).toBe(true);
    expect(result.checks.some((check) => check.id === "cisa-kev" || check.id === "critical-cvss")).toBe(false);
    expect(result.checks.find((check) => check.id === "vex-risk-acceptance")?.evidence.expiresAt).toBe("2026-12-20T12:00:00.000Z");
  });

  it("does not apply expired or package-mismatched VEX acceptances", () => {
    const result = evaluateReleasePolicy({
      scan: { ...cleanScan, findings: [{ id: "CVE-1", purl: "pkg:npm/example@1.0.0", cvssScore: 9.8 }] },
      provenance, artifactDigest: digest, now: new Date("2026-11-24T12:00:00Z"),
      riskAcceptances: [{
        exceptionId: "exception-1", advisoryId: "CVE-1", purl: "pkg:npm/example@2.0.0",
        rationale: "Affected code path is unreachable in this deployment.",
        compensatingControls: "Runtime egress policy is enabled.",
        acceptedBy: "reviewer-1", acceptedAt: "2026-11-20T12:00:00Z",
        expiresAt: "2026-11-23T12:00:00Z", status: "accepted"
      }]
    });
    expect(result.outcome).toBe("block");
    expect(result.checks.some((check) => check.id === "critical-cvss" && check.status === "block")).toBe(true);
  });
});
