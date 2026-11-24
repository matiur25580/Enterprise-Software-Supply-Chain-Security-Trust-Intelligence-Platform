export interface VexRiskAcceptanceEvidence {
  exceptionId: string;
  advisoryId: string;
  purl: string;
  rationale: string;
  compensatingControls: string;
  acceptedBy: string;
  acceptedAt: Date | string;
  expiresAt: Date | string;
  status: "accepted" | "revoked";
}

export function findActiveVexAcceptance(
  finding: { id?: string; purl?: string },
  exceptions: VexRiskAcceptanceEvidence[],
  now: Date = new Date()
): VexRiskAcceptanceEvidence | undefined {
  return exceptions.find((item) =>
    item.status === "accepted" &&
    item.advisoryId === finding.id &&
    item.purl === finding.purl &&
    Number.isFinite(new Date(item.expiresAt).getTime()) &&
    new Date(item.expiresAt).getTime() > now.getTime()
  );
}
