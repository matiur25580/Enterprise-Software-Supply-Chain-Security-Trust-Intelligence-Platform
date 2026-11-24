export const RELEASE_POLICY_VERSION = "chainproof-release-v1";

export type PolicyCheckStatus = "pass" | "warn" | "block";
export type PolicyOutcome = "pass" | "warn" | "block";
export interface PolicyCheck {
  id: string;
  status: PolicyCheckStatus;
  message: string;
  evidence: Record<string, string | number | boolean | null>;
}
export interface ReleasePolicyInput {
  riskAcceptances?: Array<{ exceptionId: string; advisoryId: string; purl: string; rationale: string; compensatingControls: string; acceptedBy: string; acceptedAt: Date | string; expiresAt: Date | string; status: "accepted" | "revoked" }>;
  scan: {
    scannedAt?: Date | string;
    findings?: Array<{
      id?: string; purl?: string; cvssScore?: number; epssScore?: number;
      isKnownExploited?: boolean; severity?: string;
    }>;
  } | null;
  provenance: { artifactDigest: string; status: string; verificationType: string } | null;
  artifactDigest: string;
  now?: Date;
}
export interface ReleasePolicyResult {
  policyVersion: string;
  outcome: PolicyOutcome;
  riskScore: number;
  checks: PolicyCheck[];
  evaluatedAt: string;
}

export function evaluateReleasePolicy(input: ReleasePolicyInput): ReleasePolicyResult {
  const checks: PolicyCheck[] = [];
  let riskScore = 0;
  const add = (check: PolicyCheck, score: number) => {
    checks.push(check);
    riskScore = Math.max(riskScore, score);
  };

  if (!input.scan) {
    add({ id: "vulnerability-scan-required", status: "block", message: "A completed vulnerability scan is required before release.", evidence: { scanPresent: false } }, 100);
  } else {
    add({ id: "vulnerability-scan-present", status: "pass", message: "A persisted vulnerability scan is available.", evidence: { scanPresent: true, findingCount: input.scan.findings?.length ?? 0 } }, 0);
    if (input.scan.scannedAt) {
      const ageDays = Math.max(0, (input.now ?? new Date()).getTime() - new Date(input.scan.scannedAt).getTime()) / 86_400_000;
      if (!Number.isFinite(ageDays) || ageDays > 30) {
        add({ id: "scan-freshness", status: "warn", message: "The latest vulnerability scan is older than 30 days or has an invalid timestamp.", evidence: { ageDays: Number.isFinite(ageDays) ? Math.round(ageDays * 10) / 10 : -1 } }, 40);
      } else {
        add({ id: "scan-freshness", status: "pass", message: "The vulnerability scan is within the 30-day freshness window.", evidence: { ageDays: Math.round(ageDays * 10) / 10 } }, 0);
      }
    }
    for (const finding of input.scan.findings ?? []) {
      const label = finding.id || "unknown-advisory";
      const acceptance = (input.riskAcceptances ?? []).find((item) =>
        item.status === "accepted" && item.advisoryId === finding.id && item.purl === finding.purl &&
        Number.isFinite(new Date(item.expiresAt).getTime()) && new Date(item.expiresAt).getTime() > (input.now ?? new Date()).getTime()
      );
      if (acceptance) {
        add({
          id: "vex-risk-acceptance",
          status: "warn",
          message: "This exact advisory/package finding has an active, time-limited risk acceptance; the vulnerability remains present and requires reassessment before expiry.",
          evidence: {
            exceptionId: acceptance.exceptionId, advisory: label, purl: finding.purl ?? null,
            rationale: acceptance.rationale, compensatingControls: acceptance.compensatingControls,
            acceptedBy: acceptance.acceptedBy, acceptedAt: new Date(acceptance.acceptedAt).toISOString(),
            expiresAt: new Date(acceptance.expiresAt).toISOString()
          }
        }, 70);
        continue;
      }
      if (finding.isKnownExploited) {
        add({ id: "cisa-kev", status: "block", message: "A component is listed in CISA Known Exploited Vulnerabilities.", evidence: { advisory: label, purl: finding.purl ?? null } }, 100);
      }
      if (typeof finding.cvssScore === "number" && finding.cvssScore >= 9) {
        add({ id: "critical-cvss", status: "block", message: "A critical vulnerability (CVSS >= 9.0) blocks release.", evidence: { advisory: label, cvssScore: finding.cvssScore } }, 95);
      } else if (typeof finding.cvssScore === "number" && finding.cvssScore >= 7) {
        add({ id: "high-cvss", status: "warn", message: "A high-severity vulnerability (CVSS >= 7.0) requires review.", evidence: { advisory: label, cvssScore: finding.cvssScore } }, 70);
      }
      if (typeof finding.epssScore === "number" && finding.epssScore >= 0.8) {
        add({ id: "high-epss", status: "block", message: "An advisory has EPSS >= 0.80, indicating high estimated exploitation probability.", evidence: { advisory: label, epssScore: finding.epssScore } }, 90);
      } else if (typeof finding.epssScore === "number" && finding.epssScore >= 0.5) {
        add({ id: "elevated-epss", status: "warn", message: "An advisory has EPSS >= 0.50 and requires risk review.", evidence: { advisory: label, epssScore: finding.epssScore } }, 65);
      }
    }
  }

  if (!input.provenance || input.provenance.status !== "verified" ||
      input.provenance.verificationType !== "sigstore-slsa-provenance" ||
      input.provenance.artifactDigest !== input.artifactDigest) {
    add({ id: "verified-provenance-required", status: "block", message: "A verified SLSA provenance record matching the exact artifact SHA-256 digest is required.", evidence: { provenancePresent: Boolean(input.provenance), digestMatched: input.provenance?.artifactDigest === input.artifactDigest } }, 100);
  } else {
    add({ id: "verified-provenance-required", status: "pass", message: "Verified SLSA provenance matches the requested artifact digest.", evidence: { provenancePresent: true, digestMatched: true } }, 0);
  }

  const outcome: PolicyOutcome = checks.some((check) => check.status === "block")
    ? "block"
    : checks.some((check) => check.status === "warn") ? "warn" : "pass";
  return {
    policyVersion: RELEASE_POLICY_VERSION,
    outcome,
    riskScore,
    checks,
    evaluatedAt: (input.now ?? new Date()).toISOString()
  };
}
