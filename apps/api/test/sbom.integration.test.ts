import express from "express";
import mongoose from "mongoose";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { SbomRecord } from "../src/models/SbomRecord";
import { VulnerabilityScan } from "../src/models/VulnerabilityScan";
const { osvQueryMock, enrichMock } = vi.hoisted(() => ({ osvQueryMock: vi.fn(), enrichMock: vi.fn() }));
vi.mock("../src/services/osvClient", () => ({ OsvServiceError: class OsvServiceError extends Error {}, queryOsvByPurls: osvQueryMock }));
vi.mock("../src/services/exploitabilityEnrichment", () => ({ enrichExploitability: enrichMock }));
import { sbomRouter } from "../src/routes/sbom";

const uri = process.env.MONGODB_URI;
const mongoAvailable = Boolean(uri);

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  const tenantId = req.header("x-test-tenant") ?? "tenant-a";
  const role = req.header("x-test-role") ?? "security-analyst";
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = { tenantId, userId: "integration-user", role };
  next();
});
app.use("/api/sboms", sbomRouter);

describe.skipIf(!mongoAvailable)("ChainProof MongoDB integration", () => {
  beforeAll(async () => {
    await mongoose.connect(uri!, { serverSelectionTimeoutMS: 10000 });
    await mongoose.connection.dropDatabase();
    await SbomRecord.syncIndexes();
  });
  beforeEach(async () => {
    await Promise.all([SbomRecord.deleteMany({}), VulnerabilityScan.deleteMany({})]);
    osvQueryMock.mockResolvedValue([{ purl: "pkg:npm/express@4.21.2", vulnerabilities: [{ id: "GHSA-integration", aliases: ["CVE-2026-1111"], references: [], summary: "Synthetic integration advisory", severity: "high", cvssScore: 8.1 }] }]);
    enrichMock.mockResolvedValue(new Map([["GHSA-integration", { epssScore: 0.31, epssPercentile: 0.88, isKnownExploited: true }]]));
  });
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

  it("ingests and normalizes a CycloneDX document into tenant-scoped inventory", async () => {
    const response = await request(app).post("/api/sboms/document").set("x-test-tenant", "tenant-a").send({
      document: {
        bomFormat: "CycloneDX", specVersion: "1.6",
        metadata: { component: { type: "application", name: "checkout", version: "3.2.1" } },
        components: [{ type: "library", name: "express", version: "4.21.2", "bom-ref": "pkg:express", purl: "pkg:npm/express@4.21.2" }],
        dependencies: [{ ref: "pkg:express", dependsOn: ["pkg:lodash"] }]
      }
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.item.ingestionStatus).toBe("validated");
    expect(response.body.item.normalizedComponents[0].purl).toBe("pkg:npm/express@4.21.2");
    expect(response.body.item.normalizedDependencies).toEqual([{ from: "pkg:express", to: "pkg:lodash", relationshipType: "dependsOn" }]);
    const inventory = await request(app).get("/api/sboms").set("x-test-tenant", "tenant-a");
    expect(inventory.body.items[0].documentName).toBe("checkout");
    const otherTenant = await request(app).get("/api/sboms").set("x-test-tenant", "tenant-b");
    expect(otherTenant.body.items).toHaveLength(0);
  });


  it("persists enriched vulnerability scan snapshots and scopes scan history by tenant", async () => {
    const ingested = await request(app).post("/api/sboms/document").set("x-test-tenant", "tenant-a").send({
      document: {
        bomFormat: "CycloneDX", specVersion: "1.6",
        metadata: { component: { type: "application", name: "checkout" } },
        components: [{ type: "library", name: "express", version: "4.21.2", purl: "pkg:npm/express@4.21.2" }]
      }
    });
    const sbomId = ingested.body.item._id;
    const scan = await request(app).post(`/api/sboms/${sbomId}/vulnerabilities`).set("x-test-tenant", "tenant-a");
    expect(scan.status).toBe(200);
    expect(scan.body.findingCount).toBe(1);
    const history = await request(app).get(`/api/sboms/${sbomId}/vulnerability-scans`).set("x-test-tenant", "tenant-a");
    expect(history.status).toBe(200);
    expect(history.body.count).toBe(1);
    expect(history.body.items[0].findings[0]).toMatchObject({
      id: "GHSA-integration", severity: "high", cvssScore: 8.1,
      epssScore: 0.31, epssPercentile: 0.88, isKnownExploited: true
    });
    const otherTenant = await request(app).get(`/api/sboms/${sbomId}/vulnerability-scans`).set("x-test-tenant", "tenant-b");
    expect(otherTenant.status).toBe(404);
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
