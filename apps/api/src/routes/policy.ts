import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { randomUUID } from "node:crypto";
import { isValidObjectId } from "mongoose";
import { z } from "zod";
import { authorize } from "../middleware/authorize";
import { SbomRecord } from "../models/SbomRecord";
import { VulnerabilityScan } from "../models/VulnerabilityScan";
import { ArtifactVerification } from "../models/ArtifactVerification";
import { PolicyEvaluation } from "../models/PolicyEvaluation";
import { ReleaseTrustPassport } from "../models/ReleaseTrustPassport";
import { createSignedReleasePassport, verifySignedReleasePassport, type SignedReleasePassport } from "../services/releasePassport";
import { evaluateReleasePolicy } from "../services/releasePolicy";

export const policyRouter = Router();
const policyLimiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false });
const evaluationInput = z.object({
  sbomId: z.string().regex(/^[a-f0-9]{24}$/i),
  artifactDigest: z.string().regex(/^[a-f0-9]{64}$/i)
}).strict();

/** Deterministic release gate: evidence must be tenant-owned and digest-bound. */
policyRouter.post("/evaluate-release", policyLimiter, authorize("platform-admin", "security-analyst", "developer"), async (request, response) => {
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
policyRouter.get("/evaluations", policyLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
    const items = await PolicyEvaluation.find({ tenantId: request.auth!.tenantId }).sort({ evaluatedAt: -1 }).limit(limit).lean();
    response.status(200).json({ items, count: items.length, limit });
  } catch {
    response.status(500).json({ error: "Unable to load policy evaluation history" });
  }
});


const passportInput = z.object({ evaluationId: z.string().regex(/^[a-f0-9]{24}$/i) }).strict();

/** Issue a portable, signed evidence envelope for a persisted release-policy evaluation. */
policyRouter.post("/release-passports", policyLimiter, authorize("platform-admin", "security-analyst", "developer"), async (request, response) => {
  const parsed = passportInput.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "Release passport input is invalid" });
    return;
  }
  if (!isValidObjectId(parsed.data.evaluationId)) {
    response.status(400).json({ error: "Invalid policy evaluation identifier" });
    return;
  }
  const privateKeyPem = process.env.RELEASE_PASSPORT_PRIVATE_KEY?.replace(/\\n/g, "\n").trim();
  if (!privateKeyPem) {
    response.status(503).json({ error: "Release passport signing is not configured" });
    return;
  }
  try {
    const tenantId = request.auth!.tenantId;
    const evaluation: any = await PolicyEvaluation.findOne({ _id: parsed.data.evaluationId, tenantId }).lean();
    if (!evaluation) {
      response.status(404).json({ error: "Policy evaluation not found" });
      return;
    }
    const [sbom, scan, provenance]: [any, any, any] = await Promise.all([
      SbomRecord.findOne({ _id: evaluation.sbomId, tenantId }).select({ _id: 1, format: 1, componentCount: 1 }).lean(),
      VulnerabilityScan.findOne({ tenantId, sbomId: evaluation.sbomId, status: "completed" }).sort({ scannedAt: -1 }).lean(),
      ArtifactVerification.findOne({
        tenantId, artifactDigest: evaluation.artifactDigest,
        verificationType: "sigstore-slsa-provenance", status: "verified"
      }).sort({ createdAt: -1 }).lean()
    ]);
    if (!sbom) {
      response.status(404).json({ error: "SBOM record not found" });
      return;
    }
    const issuedAt = new Date().toISOString();
    const passportId = randomUUID();
    const signed = createSignedReleasePassport({
      schemaVersion: "chainproof.release-trust-passport/v1",
      passportId,
      issuedAt,
      artifact: { sha256: evaluation.artifactDigest },
      sbom: { recordId: String(sbom._id), format: sbom.format, componentCount: sbom.componentCount },
      vulnerability: scan ? {
        source: "OSV",
        scannedAt: new Date(scan.scannedAt).toISOString(),
        scannedPackages: scan.scannedPackages,
        vulnerablePackages: scan.vulnerablePackages,
        findingCount: scan.findingCount,
        advisories: (scan.findings ?? []).slice(0, 100).map((finding: any) => ({
          id: finding.id,
          severity: finding.severity ?? "unknown",
          ...(typeof finding.cvssScore === "number" ? { cvssScore: finding.cvssScore } : {}),
          ...(typeof finding.epssScore === "number" ? { epssScore: finding.epssScore } : {}),
          isKnownExploited: Boolean(finding.isKnownExploited)
        }))
      } : null,
      provenance: provenance ? {
        verificationType: provenance.verificationType,
        verifiedAt: new Date(provenance.createdAt).toISOString(),
        certificateIssuer: provenance.certificateIssuer,
        certificateIdentity: provenance.certificateIdentity,
        builderId: provenance.builderId,
        sourceRepository: provenance.sourceRepository,
        sourceCommit: provenance.sourceCommit
      } : null,
      policy: {
        evaluationId: String(evaluation._id),
        version: evaluation.policyVersion,
        outcome: evaluation.outcome,
        riskScore: evaluation.riskScore,
        evaluatedAt: new Date(evaluation.evaluatedAt).toISOString(),
        checks: (evaluation.checks ?? []).map((check: any) => ({
          id: check.id, status: check.status, message: check.message
        }))
      }
    }, privateKeyPem);
    await ReleaseTrustPassport.create({
      tenantId, passportId, evaluationId: evaluation._id,
      artifactDigest: evaluation.artifactDigest, algorithm: signed.algorithm,
      keyId: signed.keyId, publicKey: signed.publicKey, payload: signed.payload,
      signature: signed.signature, signedAt: new Date(issuedAt)
    });
    response.status(201).json({ passport: signed, signatureValid: true });
  } catch (error) {
    response.status(500).json({ error: error instanceof Error && error.message.includes("Ed25519") ? error.message : "Unable to issue release trust passport" });
  }
});

/** Retrieve and cryptographically verify a tenant-owned passport. */
policyRouter.get("/release-passports/:passportId", policyLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  const passportId = z.string().uuid().safeParse(String(request.params.passportId));
  if (!passportId.success) {
    response.status(400).json({ error: "Invalid release passport identifier" });
    return;
  }
  try {
    const record: any = await ReleaseTrustPassport.findOne({
      tenantId: request.auth!.tenantId, passportId: passportId.data
    }).lean();
    if (!record) {
      response.status(404).json({ error: "Release trust passport not found" });
      return;
    }
    const passport: SignedReleasePassport = {
      algorithm: record.algorithm,
      keyId: record.keyId,
      publicKey: record.publicKey,
      payload: record.payload,
      signature: record.signature
    };
    response.status(200).json({ passport, signatureValid: verifySignedReleasePassport(passport) });
  } catch {
    response.status(500).json({ error: "Unable to verify release trust passport" });
  }
});

/** Tenant-scoped passport inventory. */
policyRouter.get("/release-passports", policyLimiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 100);
    const items = await ReleaseTrustPassport.find({ tenantId: request.auth!.tenantId })
      .select({ passportId: 1, artifactDigest: 1, keyId: 1, signedAt: 1, payload: 1 })
      .sort({ signedAt: -1 }).limit(limit).lean();
    response.status(200).json({
      items: items.map((item: any) => ({
        passportId: item.passportId, artifactDigest: item.artifactDigest,
        keyId: item.keyId, signedAt: item.signedAt,
        outcome: item.payload?.policy?.outcome, riskScore: item.payload?.policy?.riskScore
      })),
      count: items.length, limit
    });
  } catch {
    response.status(500).json({ error: "Unable to load release passport inventory" });
  }
});
