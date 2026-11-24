import { Router } from "express";
import { z } from "zod";
import { SbomRecord } from "../models/SbomRecord";

export const sbomRouter = Router();

const sbomInputSchema = z.object({
  format: z.enum(["cyclonedx", "spdx"]),
  formatVersion: z.string().min(1).max(40),
  documentName: z.string().min(1).max(200),
  documentVersion: z.string().max(100).optional(),
  componentCount: z.number().int().nonnegative().max(1000000),
  source: z.string().max(500).optional()
}).strict();

// Listing is always constrained by the tenant established by JWT middleware.
sbomRouter.get("/", async (request, response) => {
  const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
  const records = await SbomRecord.find({ tenantId: request.auth!.tenantId })
    .sort({ createdAt: -1 }).limit(limit).lean();
  response.status(200).json({ items: records });
});

// Persist only validated metadata; the actual SBOM file parser is a later milestone.
sbomRouter.post("/", async (request, response) => {
  const parsed = sbomInputSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({
      error: "SBOM metadata failed validation",
      details: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message
      }))
    });
    return;
  }

  const record = await SbomRecord.create({
    ...parsed.data,
    tenantId: request.auth!.tenantId,
    ingestionStatus: "received"
  });

  response.status(201).json({
    status: "metadata-recorded",
    message: "SBOM metadata stored. Document parsing and security analysis are not enabled yet.",
    item: record
  });
});