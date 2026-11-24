import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { find: vi.fn(), findOne: vi.fn(), create: vi.fn() } }));
vi.mock("../src/models/VulnerabilityScan", () => ({ VulnerabilityScan: { create: vi.fn(), find: vi.fn() } }));
vi.mock("../src/models/SbomIngestionJob", () => ({ SbomIngestionJob: { create: vi.fn(), findOne: vi.fn() } }));
vi.mock("../src/services/exploitabilityEnrichment", () => ({ enrichExploitability: vi.fn().mockResolvedValue(new Map([["GHSA-test", { epssScore: 0.42, epssPercentile: 0.91, isKnownExploited: true }]])) }));
vi.mock("../src/services/osvClient", () => ({ queryOsvByPurls: vi.fn(), OsvServiceError: class OsvServiceError extends Error {} }));
import { SbomRecord } from "../src/models/SbomRecord";
import { VulnerabilityScan } from "../src/models/VulnerabilityScan";
import { SbomIngestionJob } from "../src/models/SbomIngestionJob";
import { queryOsvByPurls } from "../src/services/osvClient";
import { enrichExploitability } from "../src/services/exploitabilityEnrichment";
import { sbomRouter } from "../src/routes/sbom";
const find = vi.mocked(SbomRecord.find);
const create = vi.mocked(SbomRecord.create);
const findOne = vi.mocked(SbomRecord.findOne);
const osvQuery = vi.mocked(queryOsvByPurls);
const enrich = vi.mocked(enrichExploitability);
const scanCreate = vi.mocked(VulnerabilityScan.create);
const jobCreate = vi.mocked(SbomIngestionJob.create);
const jobFindOne = vi.mocked(SbomIngestionJob.findOne);
const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = { tenantId: req.header("x-test-tenant") ?? "tenant-a", userId: "test-user", role: "security-analyst" };
  next();
});
app.use("/api/sboms", sbomRouter);
function queryResult(items: unknown[]) {
  const query = { sort: vi.fn().mockReturnThis(), limit: vi.fn().mockReturnThis(), lean: vi.fn().mockResolvedValue(items) };
  find.mockReturnValue(query as never); return query;
}
describe("tenant-scoped SBOM API", () => {
  beforeEach(() => vi.clearAllMocks());
  it("scans only PURLs from a tenant-owned SBOM and returns OSV findings", async () => {
    const record = { _id: "507f1f77bcf86cd799439011", normalizedComponents: [{ name: "express", purl: "pkg:npm/express@4.21.2" }, { name: "local", nameOnly: true }] };
    const query = { lean: vi.fn().mockResolvedValue(record) };
    findOne.mockReturnValue(query as never);
    osvQuery.mockResolvedValue([{ purl: "pkg:npm/express@4.21.2", vulnerabilities: [{ id: "GHSA-test", aliases: ["CVE-2026-1234"], references: [], summary: "Synthetic test finding", severity: "high", cvssScore: 8.1 }] }]);
    enrich.mockResolvedValue(new Map([["GHSA-test", { epssScore: 0.42, epssPercentile: 0.91, isKnownExploited: true }]]));
    scanCreate.mockResolvedValue({ _id: "scan-123", scannedAt: new Date("2026-11-24T00:00:00Z") } as never);
    const response = await request(app).post("/api/sboms/507f1f77bcf86cd799439011/vulnerabilities");
    expect(response.status).toBe(200);
    expect(findOne).toHaveBeenCalledWith({ _id: "507f1f77bcf86cd799439011", tenantId: "tenant-a" });
    expect(osvQuery).toHaveBeenCalledWith(["pkg:npm/express@4.21.2"]);
    expect(enrich).toHaveBeenCalled();
    expect(response.body.findingCount).toBe(1);
    expect(scanCreate).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", sbomId: record._id, findingCount: 1, findings: [expect.objectContaining({ cvssScore: 8.1, severity: "high", epssScore: 0.42, isKnownExploited: true })] }));
    expect(response.body.scanId).toBe("scan-123");
  });
  it("does not call OSV when an SBOM belongs to another tenant", async () => {
    const query = { lean: vi.fn().mockResolvedValue(null) };
    findOne.mockReturnValue(query as never);
    const response = await request(app).post("/api/sboms/507f1f77bcf86cd799439011/vulnerabilities");
    expect(response.status).toBe(404);
    expect(osvQuery).not.toHaveBeenCalled();
  });
  it("always scopes inventory search to authenticated tenant", async () => {
    queryResult([]);
    const response = await request(app).get("/api/sboms?q=payments&format=spdx");
    expect(response.status).toBe(200);
    expect(find).toHaveBeenCalledWith({ tenantId: "tenant-a", format: "spdx" });
  });
  it("rejects client-supplied tenant ownership", async () => {
    const response = await request(app).post("/api/sboms").send({ tenantId: "attacker-tenant", format: "cyclonedx", formatVersion: "1.6", documentName: "payments-api", componentCount: 12 });
    expect(response.status).toBe(400); expect(create).not.toHaveBeenCalled();
  });
  it("derives saved record ownership from authenticated context", async () => {
    create.mockResolvedValue({ _id: "record-2", tenantId: "tenant-a" } as never);
    const response = await request(app).post("/api/sboms").send({ format: "spdx", formatVersion: "2.3", documentName: "catalog-service", componentCount: 4 });
    expect(response.status).toBe(201);
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", documentName: "catalog-service", ingestionStatus: "received" }));
  });
  it("exports tenant-scoped CSV with escaped cell content", async () => {
    queryResult([{ documentName: 'inventory,"west"', format: "spdx", componentCount: 2 }]);
    const response = await request(app).get("/api/sboms/export.csv");
    expect(response.status).toBe(200); expect(response.headers["content-type"]).toContain("text/csv");
    expect(response.text).toContain('"inventory,""west"""'); expect(find).toHaveBeenCalledWith({ tenantId: "tenant-a" });
  });
  it("validates and persists a CycloneDX document without accepting tenant input", async () => {
    create.mockResolvedValue({ _id: "record-document", tenantId: "tenant-a", format: "cyclonedx" } as never);
    const response = await request(app).post("/api/sboms/document").send({
      document: { bomFormat: "CycloneDX", specVersion: "1.6", metadata: { component: { type: "application", name: "checkout", version: "1.0" } }, components: [{ type: "library", name: "express", version: "4.21.2", "bom-ref": "pkg:express", purl: "pkg:npm/express@4.21.2" }], dependencies: [{ ref: "pkg:express", dependsOn: ["pkg:lodash"] }] }
    });
    expect(response.status).toBe(201);
    expect(create).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a", format: "cyclonedx", documentName: "checkout", componentCount: 1,
      ingestionStatus: "validated", normalizedComponents: [expect.objectContaining({ name: "express", bomRef: "pkg:express", purl: "pkg:npm/express@4.21.2" })], normalizedDependencies: [{ from: "pkg:express", to: "pkg:lodash", relationshipType: "dependsOn" }]
    }));
  });
  it("queues raw SBOM data for background schema validation and returns a job identifier", async () => {
    jobCreate.mockResolvedValue({ _id: "507f1f77bcf86cd799439012" } as never);
    const response = await request(app).post("/api/sboms/document/async").send({
      source: "ci://build/123",
      document: {
        bomFormat: "CycloneDX", specVersion: "1.6",
        metadata: { component: { type: "application", name: "checkout", version: "1.0" } },
        components: [{ type: "library", name: "express", version: "4.21.2", purl: "pkg:npm/express@4.21.2" }]
      }
    });
    expect(response.status).toBe(202);
    expect(response.body).toMatchObject({ status: "queued", jobId: "507f1f77bcf86cd799439012" });
    expect(response.body.statusUrl).toBe("/api/sboms/ingestion-jobs/507f1f77bcf86cd799439012");
    expect(response.body.message).toContain("validation and normalization will run in the background");
    expect(jobCreate).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a", status: "queued", attempts: 0, maxAttempts: 3, source: "ci://build/123",
      rawDocument: expect.objectContaining({ bomFormat: "CycloneDX", specVersion: "1.6", components: [expect.objectContaining({ purl: "pkg:npm/express@4.21.2" })] })
    }));
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects a non-object async SBOM document before creating a job", async () => {
    const response = await request(app).post("/api/sboms/document/async").send({ document: ["not", "an", "object"] });
    expect(response.status).toBe(400);
    expect(jobCreate).not.toHaveBeenCalled();
  });

  it("rejects async SBOM documents larger than 2 MiB before creating a job", async () => {
    const response = await request(app).post("/api/sboms/document/async").send({
      document: { bomFormat: "CycloneDX", specVersion: "1.6", padding: "x".repeat(2 * 1024 * 1024) }
    });
    expect(response.status).toBe(413);
    expect(jobCreate).not.toHaveBeenCalled();
  });

  it("returns tenant-scoped ingestion job status without exposing the queued payload", async () => {
    const lean = vi.fn().mockResolvedValue({
      _id: "507f1f77bcf86cd799439012", status: "processing", attempts: 2, maxAttempts: 3,
      createdAt: new Date("2026-11-24T12:00:00Z"), updatedAt: new Date("2026-11-24T12:00:01Z")
    });
    const select = vi.fn().mockReturnValue({ lean });
    jobFindOne.mockReturnValue({ select } as never);
    const response = await request(app).get("/api/sboms/ingestion-jobs/507f1f77bcf86cd799439012");
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ status: "processing", attempts: 2, maxAttempts: 3 });
    expect(response.body.payload).toBeUndefined();
    expect(jobFindOne).toHaveBeenCalledWith({ _id: "507f1f77bcf86cd799439012", tenantId: "tenant-a" });
  });

  it("rejects malformed SBOM documents before persistence", async () => {
    const response = await request(app).post("/api/sboms/document").send({
      document: { bomFormat: "CycloneDX", specVersion: "1.3", components: [] }
    });
    expect(response.status).toBe(400);
    expect(create).not.toHaveBeenCalled();
  });
  it("returns conflict for duplicate document digests", async () => {
    create.mockRejectedValue({ code: 11000 });
    const response = await request(app).post("/api/sboms").send({ format: "cyclonedx", formatVersion: "1.6", documentName: "payments-api", componentCount: 2, documentDigest: "a".repeat(64) });
    expect(response.status).toBe(409);
  });
  it("neutralizes spreadsheet formulas in exported cells", async () => {
    queryResult([{ documentName: "=HYPERLINK(1)", format: "spdx", componentCount: 1 }]);
    const response = await request(app).get("/api/sboms/export.csv");
    expect(response.text).toContain("'=HYPERLINK(1)");
  });
});