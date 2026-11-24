import express from "express";
import mongoose from "mongoose";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { SbomRecord } from "../src/models/SbomRecord";
import { sbomRouter } from "../src/routes/sbom";

const uri = process.env.MONGODB_URI;
if (!uri) throw new Error("MONGODB_URI is required for MongoDB integration tests.");

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  const tenantId = req.header("x-test-tenant") ?? "tenant-a";
  const role = req.header("x-test-role") ?? "security-analyst";
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = { tenantId, userId: "integration-user", role };
  next();
});
app.use("/api/sboms", sbomRouter);

describe("ChainProof MongoDB integration", () => {
  beforeAll(async () => {
    await mongoose.connect(uri!, { serverSelectionTimeoutMS: 10000 });
    await mongoose.connection.dropDatabase();
    await SbomRecord.syncIndexes();
  });
  beforeEach(async () => { await SbomRecord.deleteMany({}); });
  afterAll(async () => { await mongoose.disconnect(); });

  it("persists SBOM metadata and only returns records belonging to the requesting tenant", async () => {
    const body = { format: "cyclonedx", formatVersion: "1.6", documentName: "payments-api", componentCount: 3 };
    expect((await request(app).post("/api/sboms").set("x-test-tenant", "tenant-a").send(body)).status).toBe(201);
    expect((await request(app).post("/api/sboms").set("x-test-tenant", "tenant-b").send({ ...body, documentName: "billing-api" })).status).toBe(201);

    const tenantA = await request(app).get("/api/sboms").set("x-test-tenant", "tenant-a");
    const tenantB = await request(app).get("/api/sboms").set("x-test-tenant", "tenant-b");
    expect(tenantA.status).toBe(200);
    expect(tenantA.body.items.map((item: { documentName: string }) => item.documentName)).toEqual(["payments-api"]);
    expect(tenantB.body.items.map((item: { documentName: string }) => item.documentName)).toEqual(["billing-api"]);
  });

  it("enforces the tenant-scoped unique digest index", async () => {
    const digest = "b".repeat(64);
    const body = { format: "spdx", formatVersion: "2.3", documentName: "shared-lib", componentCount: 1, documentDigest: digest };
    expect((await request(app).post("/api/sboms").set("x-test-tenant", "tenant-a").send(body)).status).toBe(201);
    expect((await request(app).post("/api/sboms").set("x-test-tenant", "tenant-a").send({ ...body, documentName: "duplicate" })).status).toBe(409);
    expect((await request(app).post("/api/sboms").set("x-test-tenant", "tenant-b").send(body)).status).toBe(201);
  });

  it("does not allow auditors to submit SBOM metadata", async () => {
    const response = await request(app).post("/api/sboms").set("x-test-role", "auditor").send({
      format: "spdx", formatVersion: "2.3", documentName: "read-only", componentCount: 0
    });
    expect(response.status).toBe(403);
    expect(await SbomRecord.countDocuments()).toBe(0);
  });
});
