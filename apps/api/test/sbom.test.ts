import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { find: vi.fn(), create: vi.fn() } }));
import { SbomRecord } from "../src/models/SbomRecord";
import { sbomRouter } from "../src/routes/sbom";
const find = vi.mocked(SbomRecord.find);
const create = vi.mocked(SbomRecord.create);
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
  it("returns conflict for duplicate document digests", async () => {
    create.mockRejectedValue({ code: 11000 });
    const response = await request(app).post("/api/sboms").send({ format: "cyclonedx", formatVersion: "1.6", documentName: "payments-api", componentCount: 2, documentDigest: "a".repeat(64) });
    expect(response.status).toBe(409);
  });
});