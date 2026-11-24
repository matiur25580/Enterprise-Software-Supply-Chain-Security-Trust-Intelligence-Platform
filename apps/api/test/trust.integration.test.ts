import express from "express";
import mongoose from "mongoose";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ArtifactVerification } from "../src/models/ArtifactVerification";
const { verifySlsaMock, verifySignatureMock, VerificationError } = vi.hoisted(() => ({
  verifySlsaMock: vi.fn(),
  verifySignatureMock: vi.fn(),
  VerificationError: class extends Error { constructor(public code: string) { super(code); } }
}));
vi.mock("../src/services/provenanceVerifier", () => ({
  verifyArtifactSignature: verifySignatureMock,
  ProvenanceVerificationError: VerificationError,
  verifySlsaProvenance: verifySlsaMock
}));
const mockSummary = {
  artifactDigest: "a".repeat(64), certificateIssuer: "https://token.actions.githubusercontent.com",
  certificateIdentity: "https://github.com/acme/release/.github/workflows/build.yml@refs/heads/main",
  predicateType: "https://slsa.dev/provenance/v1", buildType: "https://github.com/actions/runner",
  builderId: "https://github.com/acme/release/.github/workflows/build.yml@refs/heads/main",
  sourceRepository: "https://github.com/acme/release", sourceCommit: "abc123", invocationId: "run-1"
};
import { trustRouter } from "../src/routes/trust";

const uri = process.env.MONGODB_URI;
const mongoAvailable = Boolean(uri);
const app = express();
app.use(express.json({ limit: "2mb" }));
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = {
    tenantId: req.header("x-test-tenant") ?? "tenant-a", userId: "integration-user", role: "security-analyst"
  };
  next();
});
app.use("/api/trust", trustRouter);

describe.skipIf(!mongoAvailable)("ChainProof artifact verification MongoDB integration", () => {
  beforeAll(async () => {
    await mongoose.connect(uri!, { serverSelectionTimeoutMS: 10000 });
    await mongoose.connection.dropDatabase();
    await ArtifactVerification.syncIndexes();
  });
  beforeEach(async () => { await ArtifactVerification.deleteMany({}); verifySlsaMock.mockResolvedValue(mockSummary); });
  afterAll(async () => { await mongoose.disconnect(); });

  it("persists successful provenance verification and isolates audit history by tenant", async () => {
    const artifactBase64 = Buffer.from("integration-artifact").toString("base64");
    const verified = await request(app).post("/api/trust/verify-slsa-provenance")
      .set("x-test-tenant", "tenant-a")
      .send({ artifactBase64, bundle: { dsseEnvelope: { payload: "cGF5bG9hZA==" } } });
    expect(verified.status).toBe(200);
    const tenantA = await request(app).get("/api/trust/verifications").set("x-test-tenant", "tenant-a");
    expect(tenantA.status).toBe(200);
    expect(tenantA.body.count).toBe(1);
    expect(tenantA.body.items[0]).toMatchObject({
      status: "verified", tenantId: "tenant-a", verificationType: "sigstore-slsa-provenance",
      predicateType: "https://slsa.dev/provenance/v1", sourceCommit: "abc123"
    });
    const tenantB = await request(app).get("/api/trust/verifications").set("x-test-tenant", "tenant-b");
    expect(tenantB.body.count).toBe(0);
  });
});
