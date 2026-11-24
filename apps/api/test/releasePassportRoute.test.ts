import express from "express";
import request from "supertest";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/models/PolicyEvaluation", () => ({ PolicyEvaluation: { findOne: vi.fn() } }));
vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { findOne: vi.fn() } }));
vi.mock("../src/models/VulnerabilityScan", () => ({ VulnerabilityScan: { findOne: vi.fn() } }));
vi.mock("../src/models/ArtifactVerification", () => ({ ArtifactVerification: { findOne: vi.fn() } }));
vi.mock("../src/models/ReleaseTrustPassport", () => ({ ReleaseTrustPassport: { create: vi.fn(), findOne: vi.fn(), find: vi.fn() } }));

import { PolicyEvaluation } from "../src/models/PolicyEvaluation";
import { SbomRecord } from "../src/models/SbomRecord";
import { VulnerabilityScan } from "../src/models/VulnerabilityScan";
import { ArtifactVerification } from "../src/models/ArtifactVerification";
import { ReleaseTrustPassport } from "../src/models/ReleaseTrustPassport";
import { policyRouter } from "../src/routes/policy";

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = {
    tenantId: req.header("x-tenant") ?? "tenant-a", userId: "passport-test", role: "security-analyst"
  };
  next();
});
app.use("/api/policy", policyRouter);

const evaluationId = "64b000000000000000000002";
const sbomId = "64b000000000000000000001";
const digest = "a".repeat(64);
const { privateKey } = generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const evaluation = {
  _id: evaluationId, sbomId, artifactDigest: digest, policyVersion: "chainproof-release-v1",
  outcome: "pass", riskScore: 0, evaluatedAt: new Date("2026-11-24T00:00:00Z"),
  checks: [{ id: "scan", status: "pass", message: "Recent scan present" }]
};
const query = (value: unknown) => ({ sort: vi.fn().mockReturnThis(), lean: vi.fn().mockResolvedValue(value) });

describe("release trust passport API", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RELEASE_PASSPORT_PRIVATE_KEY = privatePem;
  });

  it("issues and persists a tenant-scoped signed evidence passport", async () => {
    vi.mocked(PolicyEvaluation.findOne).mockReturnValue(query(evaluation) as never);
    vi.mocked(SbomRecord.findOne).mockReturnValue({ select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue({ _id: sbomId, format: "cyclonedx", componentCount: 12 }) }) } as never);
    vi.mocked(VulnerabilityScan.findOne).mockReturnValue(query({
      scannedAt: new Date("2026-11-24T00:00:00Z"), scannedPackages: 12, vulnerablePackages: 0,
      findingCount: 0, findings: []
    }) as never);
    vi.mocked(ArtifactVerification.findOne).mockReturnValue(query({
      verificationType: "sigstore-slsa-provenance", createdAt: new Date("2026-11-24T00:00:00Z"),
      builderId: "https://github.com/example/repo/.github/workflows/release.yml"
    }) as never);
    vi.mocked(ReleaseTrustPassport.create).mockResolvedValue({ _id: "passport-record" } as never);

    const response = await request(app).post("/api/policy/release-passports").send({ evaluationId });
    expect(response.status).toBe(201);
    expect(response.body.signatureValid).toBe(true);
    expect(response.body.passport.algorithm).toBe("Ed25519");
    expect(response.body.passport.payload.policy.outcome).toBe("pass");
    expect(ReleaseTrustPassport.create).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a", evaluationId, artifactDigest: digest, algorithm: "Ed25519"
    }));
  });

  it("refuses to issue a passport when the signing key is not configured", async () => {
    delete process.env.RELEASE_PASSPORT_PRIVATE_KEY;
    const response = await request(app).post("/api/policy/release-passports").send({ evaluationId });
    expect(response.status).toBe(503);
    expect(ReleaseTrustPassport.create).not.toHaveBeenCalled();
  });

  it("does not expose a passport from another tenant", async () => {
    vi.mocked(ReleaseTrustPassport.findOne).mockReturnValue({ lean: vi.fn().mockResolvedValue(null) } as never);
    const response = await request(app).get("/api/policy/release-passports/b5d0c6e5-0d8e-4f45-9d40-8cfc4f1a0011");
    expect(response.status).toBe(404);
    expect(ReleaseTrustPassport.findOne).toHaveBeenCalledWith({
      tenantId: "tenant-a", passportId: "b5d0c6e5-0d8e-4f45-9d40-8cfc4f1a0011"
    });
  });
});
