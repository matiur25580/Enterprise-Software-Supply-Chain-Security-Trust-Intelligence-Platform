export interface ReleaseRiskCounts {
  critical: number;
  high: number;
  moderate: number;
  low: number;
  unknown: number;
}

export interface ReleaseProvenanceInput {
  sourceRepository: string;
  sourceCommitSha: string;
  builderIdentity: string;
  buildRunUrl: string;
  attestationDigest?: string | null;
}

export interface ReleaseTrustAssessment {
  trustScore: number;
  trustFactors: Array<{ key: string; points: number; explanation: string }>;
  policyStatus: "eligible" | "blocked";
  provenanceVerification: "verified" | "failed" | "untrusted_key" | "not_provided";
  policyReasons: string[];
  vulnerabilitySummary: ReleaseRiskCounts;
}

export function assessReleaseTrust(
  provenance: ReleaseProvenanceInput,
  counts: ReleaseRiskCounts,
  provenanceVerification: ReleaseTrustAssessment["provenanceVerification"] = "not_provided"
): ReleaseTrustAssessment {
  const trustFactors: ReleaseTrustAssessment["trustFactors"] = [];
  const policyReasons: string[] = [];
  let score = 100;

  const provenanceComplete = Boolean(
    provenance.sourceRepository.trim() &&
    /^[a-f0-9]{40}$/i.test(provenance.sourceCommitSha) &&
    provenance.builderIdentity.trim() &&
    /^https:\/\//i.test(provenance.buildRunUrl)
  );
  if (!provenanceComplete) {
    score -= 25;
    trustFactors.push({ key: "incomplete_provenance", points: -25, explanation: "Source repository, commit, builder identity, and HTTPS build run reference are all required for complete provenance." });
    policyReasons.push("Build provenance is incomplete.");
  } else {
    trustFactors.push({ key: "provenance_recorded", points: 0, explanation: "Source repository, commit, builder identity, and build run reference are recorded." });
  }

  if (provenanceVerification === "verified") {
    trustFactors.push({ key: "attestation_verified", points: 0, explanation: "The DSSE signature, trusted Ed25519 key, artifact subject, and signed provenance claims were verified." });
  } else {
    score -= 20;
    trustFactors.push({ key: "attestation_unverified", points: -20, explanation: "A trusted cryptographic provenance attestation has not been verified." });
    policyReasons.push("A trusted cryptographic provenance attestation is required for release eligibility.");
  }
  if (counts.critical > 0) {
    score -= Math.min(45, counts.critical * 45);
    policyReasons.push(`${counts.critical} critical open vulnerability finding(s) exceed the release policy threshold of zero.`);
    trustFactors.push({ key: "critical_vulnerabilities", points: -Math.min(45, counts.critical * 45), explanation: "Critical open vulnerability findings are present." });
  }
  if (counts.high > 0) {
    score -= Math.min(40, counts.high * 20);
    policyReasons.push(`${counts.high} high open vulnerability finding(s) exceed the release policy threshold of zero.`);
    trustFactors.push({ key: "high_vulnerabilities", points: -Math.min(40, counts.high * 20), explanation: "High open vulnerability findings are present." });
  }
  if (counts.moderate > 0) {
    score -= Math.min(15, counts.moderate * 3);
    trustFactors.push({ key: "moderate_vulnerabilities", points: -Math.min(15, counts.moderate * 3), explanation: "Moderate open vulnerability findings reduce the trust score." });
  }
  if (counts.low > 0 || counts.unknown > 0) {
    const deduction = Math.min(10, counts.low + counts.unknown);
    score -= deduction;
    trustFactors.push({ key: "low_or_unknown_vulnerabilities", points: -deduction, explanation: "Low or unknown-severity open findings reduce the trust score." });
  }

  if (counts.critical === 0 && counts.high === 0) {
    trustFactors.push({ key: "vulnerability_gate_passed", points: 0, explanation: "No critical or high open vulnerability findings were found for the associated SBOM." });
  }
  const policyStatus = policyReasons.length > 0 ? "blocked" : "eligible";
  return {
    trustScore: Math.max(0, Math.min(100, score)),
    trustFactors,
    policyStatus,
    provenanceVerification,
    policyReasons,
    vulnerabilitySummary: { ...counts }
  };
}
