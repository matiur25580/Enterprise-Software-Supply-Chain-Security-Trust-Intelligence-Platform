import { Router } from "express";
import { isValidObjectId } from "mongoose";
import { z } from "zod";
import { authorize } from "../middleware/authorize";
import { SbomRecord } from "../models/SbomRecord";
import { VulnerabilityScan } from "../models/VulnerabilityScan";
import { ArtifactVerification } from "../models/ArtifactVerification";
import { PolicyEvaluation } from "../models/PolicyEvaluation";
import { evaluateReleasePolicy } from "../services/releasePolicy";

export const policyRouter = Router();
const evaluationInput = z.object({
  sbomId: z.string().regex(/^[a-f0-9]{24}$/i),
  artifactDigest: z.string().regex(/^[a-f0-9]{64}$/i)
}).strict();

/** Deterministic release gate: evidence must be tenant-owned and digest-bound. */
policyRouter.post("/evaluate-release", authorize("platform-admin", "security-analyst", "developer"), async (request, response) => {
  const parsed = evaluationInput.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "Release policy input is invalid", details: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })) });
    return;
  }
  if (!isValidObjectId(parsed.data.sbomId)) {
    response.status(400).json({ error: "Invalid SBOM record identifier" });
    return;
  }
  try {
    const tenantId = request.auth!.tenantId;
    const sbom: any = await SbomRecord.findOne({ _id: parsed.data.sbomId, tenantId }).select({ _id: 1 }).lean();
    if (!sbom) {
      response.status(404).json({ error: "SBOM record not found" });
      return;
    }
    const [scan, provenance]: [any, any] = await Promise.all([
      VulnerabilityScan.findOne({ tenantId, sbomId: sbom._id, status: "completed" }).sort({ scannedAt: -1 }).lean(),
      ArtifactVerification.findOne({
        tenantId, artifactDigest: parsed.data.artifactDigest.toLowerCase(),
        verificationType: "sigstore-slsa-provenance", status: "verified"
      }).sort({ createdAt: -1 }).lean()
    ]);
    const result = evaluateReleasePolicy({
      scan: scan ? { scannedAt: scan.scannedAt, findings: scan.findings } : null,
      provenance: provenance ? { artifactDigest: provenance.artifactDigest, status: provenance.status, verificationType: provenance.verificationType } : null,
      artifactDigest: parsed.data.artifactDigest.toLowerCase()
    });
    const saved = await PolicyEvaluation.create({
      tenantId, sbomId: sbom._id, artifactDigest: parsed.data.artifactDigest.toLowerCase(),
      policyVersion: result.policyVersion, outcome: result.outcome, riskScore: result.riskScore,
      checks: result.checks, evaluatedAt: new Date(result.evaluatedAt)
    });
    response.status(200).json({ ...result, evaluationId: saved._id, sbomId: String(sbom._id), artifactDigest: parsed.data.artifactDigest.toLowerCase() });
  } catch {
    response.status(500).json({ error: "Unable to evaluate release policy" });
  }
});

/** Tenant-scoped release policy audit history. */
policyRouter.get("/evaluations", authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
    const items = await PolicyEvaluation.find({ tenantId: request.auth!.tenantId }).sort({ evaluatedAt: -1 }).limit(limit).lean();
    response.status(200).json({ items, count: items.length, limit });
  } catch {
    response.status(500).json({ error: "Unable to load policy evaluation history" });
  }
});
