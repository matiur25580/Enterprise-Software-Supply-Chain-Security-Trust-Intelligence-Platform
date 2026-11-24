import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { find: vi.fn(), findOne: vi.fn(), create: vi.fn() } }));
vi.mock("../src/models/VulnerabilityScan", () => ({ VulnerabilityScan: { create: vi.fn(), find: vi.fn() } }));
vi.mock("../src/services/exploitabilityEnrichment", () => ({ enrichExploitability: vi.fn().mockResolvedValue(new Map([["GHSA-test", { epssScore: 0.42, epssPercentile: 0.91, isKnownExploited: true }]])) }));
vi.mock("../src/services/osvClient", () => ({ queryOsvByPurls: vi.fn(), OsvServiceError: class OsvServiceError extends Error {} }));
import { SbomRecord } from "../src/models/SbomRecord";
import { VulnerabilityScan } from "../src/models/VulnerabilityScan";
import { queryOsvByPurls } from "../src/services/osvClient";
import { sbomRouter } from "../src/routes/sbom";
const find = vi.mocked(SbomRecord.find);
const create = vi.mocked(SbomRecord.create);
const findOne = vi.mocked(SbomRecord.findOne);
const osvQuery = vi.mocked(queryOsvByPurls);
const scanCreate = vi.mocked(VulnerabilityScan.create);
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
    scanCreate.mockResolvedValue({ _id: "scan-123", scannedAt: new Date("2026-11-24T00:00:00Z") } as never);
    const response = await request(app).post("/api/sboms/507f1f77bcf86cd799439011/vulnerabilities");
    expect(response.status).toBe(200);
    expect(findOne).toHaveBeenCalledWith({ _id: "507f1f77bcf86cd799439011", tenantId: "tenant-a" });
    expect(osvQuery).toHaveBeenCalledWith(["pkg:npm/express@4.21.2"]);
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
    expect(find).toHaveBeenCalledWith({ tenantId: "tenant-a", format: "spdx", documentName: { $regex: "payments", $options: "i" } });
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
      document: { bomFormat: "CycloneDX", specVersion: "1.6", metadata: { component: { name: "checkout", version: "1.0" } }, components: [{ type: "library", name: "express", version: "4.21.2", purl: "pkg:npm/express@4.21.2" }] }
    });
    expect(response.status).toBe(201);
    expect(create).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a", format: "cyclonedx", documentName: "checkout", componentCount: 1,
      ingestionStatus: "validated", normalizedComponents: [expect.objectContaining({ name: "express", purl: "pkg:npm/express@4.21.2" })]
    }));
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