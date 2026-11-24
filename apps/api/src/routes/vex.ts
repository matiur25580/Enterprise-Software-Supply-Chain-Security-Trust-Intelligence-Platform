import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { isValidObjectId } from "mongoose";
import { z } from "zod";
import { authorize } from "../middleware/authorize";
import { SbomRecord } from "../models/SbomRecord";
import { VulnerabilityScan } from "../models/VulnerabilityScan";
import { VexRiskAcceptance } from "../models/VexRiskAcceptance";

export const vexRouter = Router();
vexRouter.use(rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false }));

const createInput = z.object({
  sbomId: z.string().regex(/^[a-f0-9]{24}$/i),
  scanId: z.string().regex(/^[a-f0-9]{24}$/i),
  advisoryId: z.string().trim().min(1).max(120),
  purl: z.string().trim().startsWith("pkg:").max(1024),
  rationale: z.string().trim().min(20).max(2000),
  compensatingControls: z.string().trim().min(10).max(2000),
  expiresAt: z.string().datetime({ offset: true })
}).strict();

vexRouter.post("/exceptions", authorize("platform-admin", "security-analyst"), async (request, response) => {
  const parsed = createInput.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "VEX risk acceptance input is invalid", details: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })) });
    return;
  }
  const expiry = new Date(parsed.data.expiresAt);
  const now = new Date();
  if (expiry <= now || expiry.getTime() - now.getTime() > 90 * 86_400_000) {
    response.status(400).json({ error: "Risk acceptance expiry must be in the future and no more than 90 days away." });
    return;
  }
  try {
    const tenantId = request.auth!.tenantId;
    const sbom = await SbomRecord.findOne({ _id: parsed.data.sbomId, tenantId }).select({ _id: 1 }).lean();
    if (!sbom) { response.status(404).json({ error: "SBOM record not found" }); return; }
    const scan: any = await VulnerabilityScan.findOne({ _id: parsed.data.scanId, tenantId, sbomId: sbom._id, status: "completed" }).lean();
    if (!scan) { response.status(404).json({ error: "Completed vulnerability scan not found" }); return; }
    const matchingFinding = (scan.findings ?? []).some((finding: any) => finding.id === parsed.data.advisoryId && finding.purl === parsed.data.purl);
    if (!matchingFinding) { response.status(422).json({ error: "The advisory and package URL do not match a finding in the selected scan." }); return; }
    const existing = await VexRiskAcceptance.findOne({
      tenantId, sbomId: sbom._id, advisoryId: parsed.data.advisoryId, purl: parsed.data.purl,
      status: "accepted", expiresAt: { $gt: now }
    }).lean();
    if (existing) { response.status(409).json({ error: "An active risk acceptance already exists for this advisory and package." }); return; }
    const item = await VexRiskAcceptance.create({
      tenantId, sbomId: sbom._id, scanId: scan._id, advisoryId: parsed.data.advisoryId,
      purl: parsed.data.purl, rationale: parsed.data.rationale,
      compensatingControls: parsed.data.compensatingControls, status: "accepted",
      acceptedBy: request.auth!.userId, acceptedAt: now, expiresAt: expiry
    });
    response.status(201).json({ item, message: "Time-limited VEX risk acceptance recorded. It does not remove the vulnerability finding." });
  } catch {
    response.status(500).json({ error: "Unable to record VEX risk acceptance" });
  }
});

vexRouter.get("/exceptions", authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 50, 1), 100);
    const items = await VexRiskAcceptance.find({ tenantId: request.auth!.tenantId }).sort({ createdAt: -1 }).limit(limit).lean();
    const now = new Date();
    response.status(200).json({
      items: items.map((item: any) => ({ ...item, effectiveStatus: item.status === "revoked" ? "revoked" : new Date(item.expiresAt) <= now ? "expired" : "accepted" })),
      count: items.length, limit
    });
  } catch {
    response.status(500).json({ error: "Unable to load VEX risk acceptances" });
  }
});

const revokeInput = z.object({ reason: z.string().trim().min(10).max(1000) }).strict();
vexRouter.post("/exceptions/:id/revoke", authorize("platform-admin", "security-analyst"), async (request, response) => {
  if (!isValidObjectId(request.params.id)) { response.status(400).json({ error: "Invalid exception identifier" }); return; }
  const parsed = revokeInput.safeParse(request.body);
  if (!parsed.success) { response.status(400).json({ error: "Revocation reason must contain 10–1000 characters." }); return; }
  try {
    const item = await VexRiskAcceptance.findOneAndUpdate(
      { _id: request.params.id, tenantId: request.auth!.tenantId, status: "accepted" },
      { $set: { status: "revoked", revokedBy: request.auth!.userId, revokedAt: new Date(), revocationReason: parsed.data.reason } },
      { new: true, runValidators: true }
    ).lean();
    if (!item) { response.status(404).json({ error: "Active VEX risk acceptance not found" }); return; }
    response.status(200).json({ item, message: "VEX risk acceptance revoked." });
  } catch {
    response.status(500).json({ error: "Unable to revoke VEX risk acceptance" });
  }
});
