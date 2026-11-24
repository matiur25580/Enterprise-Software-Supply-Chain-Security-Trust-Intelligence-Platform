import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { createHash } from "node:crypto";
import { authorize } from "../middleware/authorize";
import { ArtifactVerification } from "../models/ArtifactVerification";
import { ProvenanceVerificationError, verifyArtifactSignature, verifySlsaProvenance } from "../services/provenanceVerifier";

export const trustRouter = Router();
const verificationLimiter = rateLimit({
  windowMs: 60_000, limit: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: "Provenance verification rate limit exceeded; retry shortly." }
});
const verificationInput = z.object({
  artifactBase64: z.string().min(4).max(1_400_000).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  bundle: z.unknown()
}).strict();

/** Verify a Cosign/Sigstore detached signature bundle against supplied artifact bytes. */
trustRouter.post("/verify-artifact-signature", authorize("platform-admin", "security-analyst", "developer"), verificationLimiter, async (request, response) => {
  const parsed = verificationInput.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "Artifact or Sigstore bundle input is invalid" });
    return;
  }
  const artifactBytes = Buffer.from(parsed.data.artifactBase64, "base64");
  if (!artifactBytes.length || artifactBytes.length > 1024 * 1024 || artifactBytes.toString("base64") !== parsed.data.artifactBase64) {
    response.status(400).json({ error: "Artifact must be canonical base64 and no larger than 1 MiB" });
    return;
  }
  const artifactDigest = createHash("sha256").update(artifactBytes).digest("hex");
  try {
    const verified = await verifyArtifactSignature(parsed.data.artifactBase64, parsed.data.bundle);
    const record = await ArtifactVerification.create({
      tenantId: request.auth!.tenantId,
      ...verified,
      digestAlgorithm: "sha256",
      verificationType: "sigstore-artifact-signature",
      status: "verified"
    });
    response.status(200).json({
      status: "verified", verificationId: record._id,
      artifactDigest: verified.artifactDigest, digestAlgorithm: "sha256",
      certificateIssuer: verified.certificateIssuer,
      certificateIdentity: verified.certificateIdentity,
      verifiedAt: record.createdAt
    });
  } catch (error) {
    if (error instanceof ProvenanceVerificationError) {
      if (error.code === "policy_not_configured") {
        response.status(503).json({ error: "Sigstore verification policy is not configured on this service" });
        return;
      }
      try {
        const record = await ArtifactVerification.create({
          tenantId: request.auth!.tenantId, artifactDigest, digestAlgorithm: "sha256",
          verificationType: "sigstore-artifact-signature", status: "rejected", failureCode: error.code
        });
        response.status(422).json({ status: "rejected", verificationId: record._id, artifactDigest, reason: error.code });
      } catch {
        response.status(500).json({ error: "Verification failed and audit record could not be saved" });
      }
      return;
    }
    response.status(500).json({ error: "Unable to complete artifact signature verification" });
  }
});

/** Verify a signed SLSA v1 provenance statement against artifact bytes. */
trustRouter.post("/verify-slsa-provenance", authorize("platform-admin", "security-analyst", "developer"), verificationLimiter, async (request, response) => {
  const parsed = verificationInput.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "Artifact or Sigstore bundle input is invalid" });
    return;
  }
  const artifactBytes = Buffer.from(parsed.data.artifactBase64, "base64");
  if (!artifactBytes.length || artifactBytes.length > 1024 * 1024 || artifactBytes.toString("base64") !== parsed.data.artifactBase64) {
    response.status(400).json({ error: "Artifact must be canonical base64 and no larger than 1 MiB" });
    return;
  }
  const artifactDigest = createHash("sha256").update(artifactBytes).digest("hex");
  try {
    const verified = await verifySlsaProvenance(parsed.data.artifactBase64, parsed.data.bundle);
    const record = await ArtifactVerification.create({
      tenantId: request.auth!.tenantId,
      ...verified,
      digestAlgorithm: "sha256",
      verificationType: "sigstore-slsa-provenance",
      status: "verified"
    });
    response.status(200).json({
      status: "verified",
      verificationId: record._id,
      artifactDigest: verified.artifactDigest,
      digestAlgorithm: "sha256",
      certificateIssuer: verified.certificateIssuer,
      certificateIdentity: verified.certificateIdentity,
      predicateType: verified.predicateType,
      buildType: verified.buildType,
      builderId: verified.builderId,
      sourceRepository: verified.sourceRepository,
      sourceCommit: verified.sourceCommit,
      invocationId: verified.invocationId,
      verifiedAt: record.createdAt
    });
  } catch (error) {
    if (error instanceof ProvenanceVerificationError) {
      if (error.code === "policy_not_configured") {
        response.status(503).json({ error: "Sigstore verification policy is not configured on this service" });
        return;
      }
      try {
        const record = await ArtifactVerification.create({
          tenantId: request.auth!.tenantId,
          artifactDigest,
          digestAlgorithm: "sha256",
          verificationType: "sigstore-slsa-provenance",
          status: "rejected",
          failureCode: error.code
        });
        response.status(422).json({ status: "rejected", verificationId: record._id, artifactDigest, reason: error.code });
      } catch {
        response.status(500).json({ error: "Verification failed and audit record could not be saved" });
      }
      return;
    }
    response.status(500).json({ error: "Unable to complete provenance verification" });
  }
});

/** Tenant-scoped verification audit history; never returns submitted bundle bytes. */
trustRouter.get("/verifications", authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
    const items = await ArtifactVerification.find({ tenantId: request.auth!.tenantId })
      .sort({ createdAt: -1 }).limit(limit).lean();
    response.status(200).json({ items, count: items.length, limit });
  } catch {
    response.status(500).json({ error: "Unable to load verification history" });
  }
});
