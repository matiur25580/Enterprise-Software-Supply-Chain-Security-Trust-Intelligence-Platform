import { randomUUID } from "node:crypto";
import mongoose from "mongoose";
import { Router, type Router as ExpressRouter } from "express";
import { z } from "zod";
import { authenticate } from "../middleware/authenticate.js";
import { requireOrganizationScope } from "../middleware/organization-scope.js";
import { requirePermission } from "../middleware/authorize.js";
import { Project } from "../models/project.js";
import { Sbom } from "../models/sbom.js";
import { VulnerabilityFinding } from "../models/vulnerability-finding.js";
import { SoftwareRelease } from "../models/software-release.js";
import { AuditEvent } from "../models/identity.js";
import { assessReleaseTrust } from "../integrations/release-trust.js";
import { parseTrustedAttestationKeys, verifyReleaseAttestation, DSSE_PAYLOAD_TYPE } from "../integrations/release-attestation.js";
import { env } from "../config/env.js";

export const releasesRouter: ExpressRouter = Router();
const base = "/organizations/:organizationId/projects/:projectId/releases";
const paramsSchema = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }).strict();
const createReleaseSchema = z.object({
  sbomId: z.string().uuid(),
  version: z.string().trim().min(1).max(128),
  artifactSha256: z.string().regex(/^[a-f0-9]{64}$/i),
  provenance: z.object({
    sourceRepository: z.string().trim().url().max(300).refine(value => value.startsWith("https://"), "Source repository must use HTTPS."),
    sourceCommitSha: z.string().regex(/^[a-f0-9]{40}$/i),
    builderIdentity: z.string().trim().min(1).max(300),
    buildRunUrl: z.string().trim().url().max(2048).refine(value => value.startsWith("https://"), "Build run URL must use HTTPS."),
    attestationDigest: z.string().regex(/^[a-f0-9]{64}$/i).optional()
  }).strict()
}).strict();
const param = (value: string | string[] | undefined): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

releasesRouter.post(base,
  authenticate, requireOrganizationScope, requirePermission("projects:write"),
  async (request, response, next) => {
    const projectId = param(request.params.projectId);
    const parsed = createReleaseSchema.safeParse(request.body);
    if (!projectId) {
      response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
      return;
    }
    if (!parsed.success) {
      response.status(400).json({ error: { code: "INVALID_RELEASE", message: "The release request is invalid.", fields: parsed.error.flatten().fieldErrors } });
      return;
    }
    try {
      const organizationId = request.auth!.orgId;
      const project = await Project.findOne({ organizationId, projectId, status: "active" }).select({ projectId: 1 }).lean();
      if (!project) {
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The active project was not found." } });
        return;
      }
      const sbom = await Sbom.findOne({ organizationId, projectId, sbomId: parsed.data.sbomId }).select({ sbomId: 1 }).lean();
      if (!sbom) {
        response.status(404).json({ error: { code: "SBOM_NOT_FOUND", message: "The SBOM does not belong to this project and organization." } });
        return;
      }
      const findings = await VulnerabilityFinding.aggregate([
        { $match: { organizationId, projectId, sbomId: parsed.data.sbomId, status: "open" } },
        { $group: { _id: "$severity", count: { $sum: 1 } } }
      ]);
      const counts = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
      for (const item of findings) {
        if (item._id in counts) counts[item._id as keyof typeof counts] = item.count;
      }
      const attestationVerification = verifyReleaseAttestation(parsed.data.attestation, {
        artifactSha256: parsed.data.artifactSha256,
        sourceRepository: parsed.data.provenance.sourceRepository,
        sourceCommitSha: parsed.data.provenance.sourceCommitSha,
        builderIdentity: parsed.data.provenance.builderIdentity,
        buildRunUrl: parsed.data.provenance.buildRunUrl
      }, parseTrustedAttestationKeys(env.CHAINPROOF_ATTESTATION_TRUSTED_KEYS));
      const assessment = assessReleaseTrust(parsed.data.provenance, counts, attestationVerification.status);
      const releaseId = randomUUID();
      // Persist the release and its audit event atomically. A failed audit write
      // must never leave an un-audited release record behind.
      const session = await mongoose.startSession();
      let release: InstanceType<typeof SoftwareRelease> | undefined;
      try {
        await session.withTransaction(async () => {
          const [createdRelease] = await SoftwareRelease.create([{
            releaseId, organizationId, projectId, sbomId: parsed.data.sbomId,
            version: parsed.data.version, artifactSha256: parsed.data.artifactSha256,
            provenance: parsed.data.provenance, provenanceVerification: "not_verified",
            ...assessment, createdByUserId: request.auth!.sub
          }], { session });
          await AuditEvent.create([{
            eventId: randomUUID(), organizationId, actorUserId: request.auth!.sub,
            action: "release.assessed", targetType: "software_release", targetId: releaseId,
            metadata: { projectId, sbomId: parsed.data.sbomId, version: parsed.data.version, artifactSha256: parsed.data.artifactSha256, trustScore: assessment.trustScore, policyStatus: assessment.policyStatus, provenanceVerification: attestationVerification.status, attestationKeyId: attestationVerification.keyId, attestationEnvelopeSha256: attestationVerification.envelopeSha256, vulnerabilitySummary: assessment.vulnerabilitySummary }
          }], { session });
          release = createdRelease;
        });
      } finally {
        await session.endSession();
      }
      if (!release) throw new Error("Release transaction completed without returning a release.");
      response.status(201).json({ data: release.toJSON() });
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === 11000) {
        response.status(409).json({ error: { code: "RELEASE_ALREADY_RECORDED", message: "This release version and artifact digest are already recorded for the project." } });
        return;
      }
      next(error);
    }
  }
);

releasesRouter.get(base,
  authenticate, requireOrganizationScope, requirePermission("projects:read"),
  async (request, response, next) => {
    const projectId = param(request.params.projectId);
    const parsed = paramsSchema.safeParse(request.query);
    if (!projectId) {
      response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
      return;
    }
    if (!parsed.success) {
      response.status(400).json({ error: { code: "INVALID_QUERY", message: "The release list query is invalid." } });
      return;
    }
    try {
      const organizationId = request.auth!.orgId;
      const project = await Project.findOne({ organizationId, projectId }).select({ projectId: 1 }).lean();
      if (!project) {
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      const data = await SoftwareRelease.find({ organizationId, projectId })
        .sort({ createdAt: -1 }).limit(parsed.data.limit).lean();
      response.status(200).json({ data });
    } catch (error) { next(error); }
  }
);

releasesRouter.get(`${base}/:releaseId`,
  authenticate, requireOrganizationScope, requirePermission("projects:read"),
  async (request, response, next) => {
    const projectId = param(request.params.projectId), releaseId = param(request.params.releaseId);
    if (!projectId || !releaseId) {
      response.status(404).json({ error: { code: "RELEASE_NOT_FOUND", message: "The release was not found." } });
      return;
    }
    try {
      const data = await SoftwareRelease.findOne({
        organizationId: request.auth!.orgId, projectId, releaseId
      }).lean();
      if (!data) {
        response.status(404).json({ error: { code: "RELEASE_NOT_FOUND", message: "The release was not found." } });
        return;
      }
      response.status(200).json({ data });
    } catch (error) { next(error); }
  }
);
