import express from "express";
import request from "supertest";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/models/ReleasePassportSigner", () => ({
  ReleasePassportSigner: {
    find: vi.fn(), findOne: vi.fn(), findOneAndUpdate: vi.fn(), updateMany: vi.fn()
  }
}));

import { ReleasePassportSigner } from "../src/models/ReleasePassportSigner";
import { signerRouter } from "../src/routes/signers";

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = {
    tenantId: req.header("x-tenant") ?? "tenant-a", userId: "signer-test", role: "platform-admin"
  };
  next();
});
app.use("/api/policy", signerRouter);

const { privateKey } = generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const query = (value: unknown) => ({
  sort: vi.fn().mockReturnThis(), select: vi.fn().mockReturnThis(),
  limit: vi.fn().mockReturnThis(), lean: vi.fn().mockResolvedValue(value)
});

describe("release passport signer lifecycle API", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RELEASE_PASSPORT_PRIVATE_KEY = privatePem;
    vi.mocked(ReleasePassportSigner.findOne).mockReturnValue(query(null) as never);
    vi.mocked(ReleasePassportSigner.updateMany).mockResolvedValue({ modifiedCount: 0 } as never);
    vi.mocked(ReleasePassportSigner.findOneAndUpdate).mockReturnValue(query({
      keyId: "b".repeat(64), status: "active"
    }) as never);
  });

  it("activates only the public key derived from the server secret", async () => {
    const response = await request(app).post("/api/policy/release-signers/rotate").send({});
    expect(response.status).toBe(200);
    expect(response.body.signer.status).toBe("active");
    expect(response.body.signer.keyId).toMatch(/^[a-f0-9]{64}$/);
    expect(ReleasePassportSigner.updateMany).toHaveBeenCalledWith(
      { tenantId: "tenant-a", status: "active" },
      expect.objectContaining({ $set: expect.objectContaining({ status: "retired" }) })
    );
    expect(ReleasePassportSigner.findOneAndUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId: "tenant-a" }),
      expect.objectContaining({ $set: expect.objectContaining({ algorithm: "Ed25519" }) }),
      expect.objectContaining({ upsert: true, new: true })
    );
  });

  it("requires an expected current fingerprint when one is supplied", async () => {
    vi.mocked(ReleasePassportSigner.findOne).mockReturnValue(query({ keyId: "a".repeat(64) }) as never);
    const response = await request(app).post("/api/policy/release-signers/rotate")
      .send({ expectedCurrentKeyId: "c".repeat(64) });
    expect(response.status).toBe(409);
    expect(ReleasePassportSigner.updateMany).not.toHaveBeenCalled();
  });

  it("requires a reason when revoking a key", async () => {
    const response = await request(app).post("/api/policy/release-signers/revoke")
      .send({ keyId: "a".repeat(64), reason: "bad" });
    expect(response.status).toBe(400);
    expect(ReleasePassportSigner.findOneAndUpdate).not.toHaveBeenCalled();
  });
});
