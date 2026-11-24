import { Router } from "express";
import { authorize } from "../middleware/authorize";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { isValidObjectId } from "mongoose";
import { SbomRecord } from "../models/SbomRecord";
import { parseSbomDocument, SbomValidationError } from "../services/sbomParser";
import { queryOsvByPurls, OsvServiceError } from "../services/osvClient";
import { enrichExploitability } from "../services/exploitabilityEnrichment";
import { VulnerabilityScan } from "../models/VulnerabilityScan";

const sbomReadLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false });
const intakeLimiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: "SBOM intake rate limit exceeded; retry shortly." } });
const vulnerabilityLimiter = rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Vulnerability scan rate limit exceeded; retry shortly." } });
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
function csvCell(value: unknown): string {
  const raw = value == null ? "" : String(value);
  // Prevent spreadsheet formula execution when a CSV is opened in office tools.
  const first = raw[0];
  const safe = first === "=" || first === "+" || first === "-" || first === "@" || first === "\t" || first === "\r"
    ? `'${raw}`
    : raw;
  return `"${safe.replace(/"/g, '""')}"`;
}
sbomRouter.get("/export.csv", sbomReadLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const records = await SbomRecord.find({ tenantId: request.auth!.tenantId }).sort({ createdAt: -1 }).limit(5000).lean();
    const columns = ["documentName", "documentVersion", "format", "formatVersion", "componentCount", "documentDigest", "createdAt"];
    const rows = records.map((record: Record<string, unknown>) => columns.map((column) => csvCell(record[column])).join(","));
    response.setHeader("Content-Type", "text/csv; charset=utf-8").setHeader("Content-Disposition", 'attachment; filename="chainproof-sbom-inventory.csv"').status(200).send([columns.join(","), ...rows].join("\r\n"));
  } catch { response.status(500).json({ error: "Unable to export SBOM inventory" }); }
});
sbomRouter.get("/", sbomReadLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
    const filter: Record<string, unknown> = { tenantId: request.auth!.tenantId };
    if (request.query.format === "cyclonedx") filter.format = "cyclonedx";
    else if (request.query.format === "spdx") filter.format = "spdx";
    // Search is applied in memory to a bounded tenant-scoped result set, never interpolated into MongoDB operators.
    const records = await SbomRecord.find(filter).sort({ createdAt: -1 }).limit(5000).lean();
    const searchTerm = typeof request.query.q === "string" ? request.query.q.trim().slice(0, 80).toLowerCase() : "";
    const filtered = searchTerm
      ? records.filter((record: any) => String(record.documentName ?? "").toLowerCase().includes(searchTerm)).slice(0, limit)
      : records.slice(0, limit);
    response.status(200).json({ items: filtered, count: filtered.length, limit });
  } catch { response.status(500).json({ error: "Unable to load SBOM inventory" }); }
});


/** On-demand OSV lookup for one tenant-owned SBOM; results are not persisted. */
sbomRouter.post("/:id/vulnerabilities", sbomReadLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), vulnerabilityLimiter, async (request, response) => {
  if (!isValidObjectId(request.params.id)) {
    response.status(400).json({ error: "Invalid SBOM record identifier" });
    return;
  }
  try {
    const record: any = await SbomRecord.findOne({ _id: request.params.id, tenantId: request.auth!.tenantId }).lean();
    if (!record) {
      response.status(404).json({ error: "SBOM record not found" });
      return;
    }
    const components = Array.isArray(record.normalizedComponents) ? record.normalizedComponents : [];
    const purls: string[] = [...new Set<string>(components.flatMap((component: Record<string, unknown>) =>
      typeof component.purl === "string" ? [component.purl] : []
    ))];
    if (purls.length > 100) {
      response.status(422).json({ error: "This SBOM has more than 100 package URLs; split it into smaller inventories before scanning." });
      return;
    }
    if (purls.length === 0) {
      response.status(200).json({ status: "completed", source: "OSV", scannedPackages: 0, vulnerablePackages: 0, findings: [], message: "No package URLs were available for vulnerability lookup." });
      return;
    }
    const results = await queryOsvByPurls(purls);
    const allVulnerabilities = results.flatMap((result) => result.vulnerabilities);
    const enrichment = await enrichExploitability(allVulnerabilities);
    const findings = results.flatMap((result) => result.vulnerabilities.map((vulnerability) => ({
      purl: result.purl,
      ...vulnerability,
      ...(enrichment.get(vulnerability.id) ?? { isKnownExploited: false })
    })));
    const scan = await VulnerabilityScan.create({
      tenantId: request.auth!.tenantId,
      sbomId: record._id,
      source: "OSV",
      status: "completed",
      scannedPackages: results.length,
      vulnerablePackages: results.filter((result) => result.vulnerabilities.length > 0).length,
      findingCount: findings.length,
      findings,
      scannedAt: new Date()
    });
    response.status(200).json({
      status: "completed",
      source: "OSV",
      scanId: scan._id,
      scannedAt: scan.scannedAt,
      scannedPackages: results.length,
      vulnerablePackages: results.filter((result) => result.vulnerabilities.length > 0).length,
      findingCount: findings.length,
      findings
    });
  } catch (error) {
    console.error("SBOM vulnerability scan failed:", error instanceof Error ? error.message : "unknown error");
    if (error instanceof OsvServiceError) {
      response.status(502).json({ error: "Vulnerability lookup could not be completed", reason: error.message });
      return;
    }
    response.status(500).json({ error: "Unable to scan SBOM vulnerabilities" });
  }
});


/** Latest persisted vulnerability scan snapshots for a tenant-owned SBOM. */
sbomRouter.get("/:id/vulnerability-scans", sbomReadLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  if (!isValidObjectId(request.params.id)) {
    response.status(400).json({ error: "Invalid SBOM record identifier" });
    return;
  }
  try {
    const record: any = await SbomRecord.findOne({ _id: request.params.id, tenantId: request.auth!.tenantId }).select({ _id: 1 }).lean();
    if (!record) {
      response.status(404).json({ error: "SBOM record not found" });
      return;
    }
    const scans = await VulnerabilityScan.find({ tenantId: request.auth!.tenantId, sbomId: record._id })
      .sort({ scannedAt: -1 }).limit(20).lean();
    response.status(200).json({ items: scans, count: scans.length });
  } catch {
    response.status(500).json({ error: "Unable to load vulnerability scan history" });
  }
});

/** Accepts a bounded JSON CycloneDX or SPDX document; raw documents are not retained. */
sbomRouter.post("/document", sbomReadLimiter, authorize("platform-admin", "security-analyst", "developer"), intakeLimiter, async (request, response) => {
  const input = z.object({ document: z.unknown(), source: z.string().max(500).optional() }).strict().safeParse(request.body);
  if (!input.success) {
    response.status(400).json({ error: "SBOM upload request is invalid" });
    return;
  }
  try {
    const parsed = parseSbomDocument(input.data.document);
    const record = await SbomRecord.create({
      ...parsed,
      source: input.data.source,
      tenantId: request.auth!.tenantId,
      ingestionStatus: "validated"
    });
    response.status(201).json({
      status: "validated",
      message: "SBOM passed the official format schema and was normalized, including dependency relationships. Artifact signature and provenance verification are available through the separate trust API.",
      item: record
    });
  } catch (error) {
    if (error instanceof SbomValidationError) {
      response.status(400).json({ error: "SBOM document failed validation", reason: error.message });
      return;
    }
    if (typeof error === "object" && error !== null && "code" in error && error.code === 11000) {
      response.status(409).json({ error: "An SBOM with this digest already exists in this tenant." });
      return;
    }
    response.status(500).json({ error: "Unable to ingest SBOM document" });
  }
});

sbomRouter.post("/", sbomReadLimiter, authorize("platform-admin", "security-analyst", "developer"), intakeLimiter, async (request, response) => {
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