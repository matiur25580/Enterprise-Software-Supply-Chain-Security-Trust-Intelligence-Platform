import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { findOne: vi.fn() } }));
vi.mock("../src/models/VulnerabilityScan", () => ({ VulnerabilityScan: { findOne: vi.fn() } }));
vi.mock("../src/models/VexRiskAcceptance", () => ({ VexRiskAcceptance: { create: vi.fn(), findOne: vi.fn(), find: vi.fn(), findOneAndUpdate: vi.fn() } }));

import { SbomRecord } from "../src/models/SbomRecord";
import { VulnerabilityScan } from "../src/models/VulnerabilityScan";
import { VexRiskAcceptance } from "../src/models/VexRiskAcceptance";
import { vexRouter } from "../src/routes/vex";

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  (req as typeof req & { auth: { tenantId: string; userId: string; role: string } }).auth = { tenantId: "tenant-a", userId: "reviewer-1", role: "security-analyst" };
  next();
});
app.use("/api/vex", vexRouter);
const sbomId = "64b000000000000000000001";
const scanId = "64b000000000000000000002";
const purl = "pkg:npm/example@1.0.0";
const expiry = "2026-12-20T12:00:00.000Z";
const query = (value: unknown) => ({ select: vi.fn().mockReturnThis(), lean: vi.fn().mockResolvedValue(value) });

describe("VEX risk acceptance API", () => {
  beforeEach(() => vi.clearAllMocks());

  it("records a time-limited acceptance only for a finding in a tenant-owned scan", async () => {
    vi.mocked(SbomRecord.findOne).mockReturnValue(query({ _id: sbomId }) as never);
    vi.mocked(VulnerabilityScan.findOne).mockReturnValue(query({ _id: scanId, findings: [{ id: "GHSA-1", purl }] }) as never);
    vi.mocked(VexRiskAcceptance.findOne).mockReturnValue(query(null) as never);
    vi.mocked(VexRiskAcceptance.create).mockResolvedValue({ _id: "exception-1", status: "accepted" } as never);
    const response = await request(app).post("/api/vex/exceptions").send({
      sbomId, scanId, advisoryId: "GHSA-1", purl,
      rationale: "The affected code path is unreachable in this deployment.",
      compensatingControls: "Runtime policy and request validation are enabled.",
      expiresAt: expiry
    });
    expect(response.status).toBe(201);
    expect(VexRiskAcceptance.create).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a", acceptedBy: "reviewer-1", advisoryId: "GHSA-1", purl, status: "accepted"
    }));
  });

  it("rejects acceptance when the advisory and package URL do not match the scan", async () => {
    vi.mocked(SbomRecord.findOne).mockReturnValue(query({ _id: sbomId }) as never);
    vi.mocked(VulnerabilityScan.findOne).mockReturnValue(query({ _id: scanId, findings: [{ id: "GHSA-other", purl }] }) as never);
    const response = await request(app).post("/api/vex/exceptions").send({
      sbomId, scanId, advisoryId: "GHSA-1", purl,
      rationale: "The affected code path is unreachable in this deployment.",
      compensatingControls: "Runtime policy and request validation are enabled.",
      expiresAt: expiry
    });
    expect(response.status).toBe(422);
    expect(VexRiskAcceptance.create).not.toHaveBeenCalled();
  });

  it("rejects acceptance windows longer than 90 days", async () => {
    const response = await request(app).post("/api/vex/exceptions").send({
      sbomId, scanId, advisoryId: "GHSA-1", purl,
      rationale: "The affected code path is unreachable in this deployment.",
      compensatingControls: "Runtime policy and request validation are enabled.",
      expiresAt: "2027-05-01T00:00:00.000Z"
    });
    expect(response.status).toBe(400);
    expect(SbomRecord.findOne).not.toHaveBeenCalled();
  });
});
