import { Router } from "express";
import { z } from "zod";

export const sbomRouter = Router();

const sbomInputSchema = z.object({
  format: z.enum(["cyclonedx", "spdx"]),
  formatVersion: z.string().min(1).max(40),
  documentName: z.string().min(1).max(200),
  documentVersion: z.string().max(100).optional(),
  componentCount: z.number().int().nonnegative().max(1000000),
  source: z.string().max(500).optional()
}).strict();

// This first milestone validates intake metadata only. It deliberately does
// not claim to parse, persist, or trust an SBOM document until the dedicated
// ingestion pipeline, storage adapter, and schema-specific validators exist.
sbomRouter.post("/", (request, response) => {
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

  response.status(202).json({
    status: "accepted-for-validation",
    message: "Metadata accepted; document ingestion is not enabled in this milestone.",
    sbom: parsed.data
  });
});