import { Router } from "express";
import { z } from "zod";
import { SbomRecord } from "../models/SbomRecord";
export const sbomRouter = Router();
const sbomInputSchema = z.object({
  format: z.enum(["cyclonedx", "spdx"]),
  formatVersion: z.string().trim().min(1).max(40),
  documentName: z.string().trim().min(1).max(200),
  documentVersion: z.string().max(100).optional(),
  componentCount: z.number().int().nonnegative().max(1000000),
  source: z.string().max(500).optional(),
  documentDigest: z.string().regex(/^[a-f0-9]{64}$/i).optional()
}).strict();
function escapeRegex(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function csvCell(value: unknown): string {
  const text = value == null ? "" : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}
sbomRouter.get("/export.csv", async (request, response) => {
  try {
    const records = await SbomRecord.find({ tenantId: request.auth!.tenantId }).sort({ createdAt: -1 }).limit(5000).lean();
    const columns = ["documentName", "documentVersion", "format", "formatVersion", "componentCount", "documentDigest", "createdAt"];
    const rows = records.map((record: Record<string, unknown>) => columns.map((column) => csvCell(record[column])).join(","));
    response.setHeader("Content-Type", "text/csv; charset=utf-8").setHeader("Content-Disposition", 'attachment; filename="chainproof-sbom-inventory.csv"').status(200).send([columns.join(","), ...rows].join("\r\n"));
  } catch { response.status(500).json({ error: "Unable to export SBOM inventory" }); }
});
sbomRouter.get("/", async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
    const filter: Record<string, unknown> = { tenantId: request.auth!.tenantId };
    if (request.query.format === "cyclonedx" || request.query.format === "spdx") filter.format = request.query.format;
    if (typeof request.query.q === "string" && request.query.q.trim()) filter.documentName = { $regex: escapeRegex(request.query.q.trim().slice(0, 80)), $options: "i" };
    const records = await SbomRecord.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    response.status(200).json({ items: records, count: records.length, limit });
  } catch { response.status(500).json({ error: "Unable to load SBOM inventory" }); }
});
sbomRouter.post("/", async (request, response) => {
  const parsed = sbomInputSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "SBOM metadata failed validation", details: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })) });
    return;
  }
  try {
    const record = await SbomRecord.create({ ...parsed.data, tenantId: request.auth!.tenantId, ingestionStatus: "received" });
    response.status(201).json({ status: "metadata-recorded", message: "SBOM metadata stored. Document parsing and security analysis are not enabled yet.", item: record });
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === 11000) {
      response.status(409).json({ error: "An SBOM with this digest already exists in this tenant." }); return;
    }
    response.status(500).json({ error: "Unable to save SBOM metadata" });
  }
});