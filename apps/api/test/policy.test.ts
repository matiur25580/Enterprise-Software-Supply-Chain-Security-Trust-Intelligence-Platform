import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { findOne: vi.fn() } }));
vi.mock("../src/models/VulnerabilityScan", () => ({ VulnerabilityScan: { findOne: vi.fn() } }));
vi.mock("../src/models/ArtifactVerification", () => ({ ArtifactVerification: { findOne: vi.fn() } }));
vi.mock("../src/models/PolicyEvaluation", () => ({ PolicyEvaluation: { create: vi.fn(), find: vi.fn() } }));

import { SbomRecord } from "../src/models/SbomRecord";
import { VulnerabilityScan } from "../src/models/VulnerabilityScan";
import { ArtifactVerification } from "../src/models/ArtifactVerification";
import { PolicyEvaluation } from "../src/models/PolicyEvaluation";
import { policyRouter } from "../src/routes/policy";

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = {
    tenantId: req.header("x-tenant") ?? "tenant-a", userId: "policy-test", role: "security-analyst"
  };
  next();
});
app.use("/api/policy", policyRouter);

const digest = "a".repeat(64);
const sbomId = "64b000000000000000000001";
const query = (value: unknown) => ({ sort: vi.fn().mockReturnThis(), lean: vi.fn().mockResolvedValue(value) });

describe("release policy API", () => {
  beforeEach(() => vi.clearAllMocks());

  it("evaluates only tenant-owned SBOM evidence and stores the policy decision", async () => {
    vi.mocked(SbomRecord.findOne).mockReturnValue({ select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue({ _id: sbomId }) }) } as never);
    vi.mocked(VulnerabilityScan.findOne).mockReturnValue(query({ scannedAt: new Date(), findings: [] }) as never);
    vi.mocked(ArtifactVerification.findOne).mockReturnValue(query({ artifactDigest: digest, status: "verified", verificationType: "sigstore-slsa-provenance" }) as never);
    vi.mocked(PolicyEvaluation.create).mockResolvedValue({ _id: "evaluation-1" } as never);

    const response = await request(app).post("/api/policy/evaluate-release").send({ sbomId, artifactDigest: digest });
    expect(response.status).toBe(200);
    expect(response.body.outcome).toBe("pass");
    expect(PolicyEvaluation.create).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", outcome: "pass", artifactDigest: digest }));
    expect(SbomRecord.findOne).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", _id: expect.objectContaining({ _bsontype: "ObjectId" }) }));
    expect(VulnerabilityScan.findOne).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", sbomId }));
  });

  it("blocks when no scan or matching provenance is available", async () => {
    vi.mocked(SbomRecord.findOne).mockReturnValue({ select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue({ _id: sbomId }) }) } as never);
    vi.mocked(VulnerabilityScan.findOne).mockReturnValue(query(null) as never);
    vi.mocked(ArtifactVerification.findOne).mockReturnValue(query(null) as never);
    vi.mocked(PolicyEvaluation.create).mockResolvedValue({ _id: "evaluation-2" } as never);

    const response = await request(app).post("/api/policy/evaluate-release").send({ sbomId, artifactDigest: digest });
    expect(response.status).toBe(200);
    expect(response.body.outcome).toBe("block");
    expect(response.body.checks.map((check: { id: string }) => check.id)).toContain("verified-provenance-required");
  });

  it("rejects malformed digests and does not query evidence", async () => {
    const response = await request(app).post("/api/policy/evaluate-release").send({ sbomId, artifactDigest: "bad" });
    expect(response.status).toBe(400);
    expect(SbomRecord.findOne).not.toHaveBeenCalled();
  });

  it("returns not found for an SBOM outside the authenticated tenant", async () => {
    vi.mocked(SbomRecord.findOne).mockReturnValue({ select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(null) }) } as never);
    const response = await request(app).post("/api/policy/evaluate-release").send({ sbomId, artifactDigest: digest });
    expect(response.status).toBe(404);
    expect(VulnerabilityScan.findOne).not.toHaveBeenCalled();
  });
});
