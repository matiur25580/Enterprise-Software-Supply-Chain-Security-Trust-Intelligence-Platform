import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/models/ArtifactVerification", () => ({ ArtifactVerification: { create: vi.fn(), find: vi.fn() } }));
vi.mock("../src/services/provenanceVerifier", () => ({
  verifySlsaProvenance: vi.fn(),
  ProvenanceVerificationError: class ProvenanceVerificationError extends Error { constructor(public code: string) { super(code); } }
}));
import { ArtifactVerification } from "../src/models/ArtifactVerification";
import { verifySlsaProvenance, ProvenanceVerificationError } from "../src/services/provenanceVerifier";
import { trustRouter } from "../src/routes/trust";

const create = vi.mocked(ArtifactVerification.create);
const find = vi.mocked(ArtifactVerification.find);
const verifyProvenance = vi.mocked(verifySlsaProvenance);
const app = express();
app.use(express.json({ limit: "2mb" }));
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = {
    tenantId: req.header("x-test-tenant") ?? "tenant-a", userId: "trust-test", role: req.header("x-test-role") ?? "security-analyst"
  };
  next();
});
app.use("/api/trust", trustRouter);
const artifactBase64 = Buffer.from("artifact").toString("base64");
const summary = {
  artifactDigest: "a".repeat(64), certificateIssuer: "https://token.actions.githubusercontent.com",
  certificateIdentity: "https://github.com/acme/project/.github/workflows/release.yml@refs/heads/main",
  predicateType: "https://slsa.dev/provenance/v1", buildType: "https://github.com/actions/runner",
  builderId: "https://github.com/acme/project/.github/workflows/release.yml@refs/heads/main",
  sourceRepository: "https://github.com/acme/project", sourceCommit: "abc123", invocationId: "run-42"
};
describe("tenant-scoped trust verification API", () => {
  beforeEach(() => vi.clearAllMocks());
  it("persists successful provenance verification without storing artifact or bundle bytes", async () => {
    verifyProvenance.mockResolvedValue(summary);
    create.mockResolvedValue({ _id: "verification-1", createdAt: new Date("2026-11-24T00:00:00Z") } as never);
    const response = await request(app).post("/api/trust/verify-slsa-provenance").send({ artifactBase64, bundle: { dsseEnvelope: { payload: "cGF5bG9hZA==" } } });
    expect(response.status).toBe(200);
    expect(response.body.status).toBe("verified");
    expect(create).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a", artifactDigest: summary.artifactDigest, status: "verified",
      verificationType: "sigstore-slsa-provenance", builderId: summary.builderId
    }));
    expect(JSON.stringify(create.mock.calls[0][0])).not.toContain(artifactBase64);
  });
  it("records rejected verification with a stable failure code", async () => {
    const failure = new ProvenanceVerificationError("artifact_digest_mismatch");
    verifyProvenance.mockRejectedValue(failure);
    create.mockResolvedValue({ _id: "verification-2" } as never);
    const response = await request(app).post("/api/trust/verify-slsa-provenance").send({ artifactBase64, bundle: {} });
    expect(response.status).toBe(422);
    expect(response.body.reason).toBe("artifact_digest_mismatch");
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", status: "rejected", failureCode: "artifact_digest_mismatch" }));
  });
  it("returns service unavailable when server verification policy is missing", async () => {
    verifyProvenance.mockRejectedValue(new ProvenanceVerificationError("policy_not_configured"));
    const response = await request(app).post("/api/trust/verify-slsa-provenance").send({ artifactBase64, bundle: {} });
    expect(response.status).toBe(503);
    expect(create).not.toHaveBeenCalled();
  });
  it("scopes verification history to the authenticated tenant", async () => {
    const query = { sort: vi.fn().mockReturnThis(), limit: vi.fn().mockReturnThis(), lean: vi.fn().mockResolvedValue([]) };
    find.mockReturnValue(query as never);
    const response = await request(app).get("/api/trust/verifications");
    expect(response.status).toBe(200);
    expect(find).toHaveBeenCalledWith({ tenantId: "tenant-a" });
  });
  it("rejects malformed artifact encodings before verification", async () => {
    const response = await request(app).post("/api/trust/verify-slsa-provenance").send({ artifactBase64: "not base64!", bundle: {} });
    expect(response.status).toBe(400);
    expect(verifyProvenance).not.toHaveBeenCalled();
  });
});
