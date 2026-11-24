import { beforeEach, describe, expect, it, vi } from "vitest";

const { claimMock, updateJobMock, recoverMock, persistMock, parseMock } = vi.hoisted(() => ({
  claimMock: vi.fn(),
  updateJobMock: vi.fn(),
  recoverMock: vi.fn(),
  persistMock: vi.fn(),
  parseMock: vi.fn()
}));

vi.mock("../src/models/SbomIngestionJob", () => ({
  SbomIngestionJob: {
    findOneAndUpdate: claimMock,
    updateOne: updateJobMock,
    updateMany: recoverMock
  }
}));
vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { findOneAndUpdate: persistMock } }));
vi.mock("../src/services/sbomParser", () => ({
  parseSbomDocument: parseMock,
  SbomValidationError: class SbomValidationError extends Error {}
}));

import { processNextSbomIngestionJob } from "../src/services/sbomIngestionWorker";
import { SbomValidationError } from "../src/services/sbomParser";

const parsed = {
  format: "cyclonedx",
  formatVersion: "1.6",
  documentName: "checkout",
  componentCount: 1,
  documentDigest: "a".repeat(64),
  normalizedComponents: [{ name: "express", purl: "pkg:npm/express@4.21.2" }],
  normalizedDependencies: []
};
const rawDocument = { bomFormat: "CycloneDX", specVersion: "1.6", components: [] };

function claimedJob(overrides: Record<string, unknown> = {}) {
  return {
    _id: "507f1f77bcf86cd799439011",
    tenantId: "tenant-a",
    status: "processing",
    rawDocument,
    source: "ci://test",
    attempts: 1,
    maxAttempts: 3,
    ...overrides
  };
}

describe("durable SBOM ingestion worker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    recoverMock.mockResolvedValue({ modifiedCount: 0 });
    parseMock.mockReturnValue(parsed);
    updateJobMock.mockResolvedValue({ modifiedCount: 1 });
  });

  it("validates a claimed raw document and persists its normalized SBOM idempotently", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob()) });
    persistMock.mockReturnValue({ lean: vi.fn().mockResolvedValue({ _id: "sbom-1" }) });

    await expect(processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"))).resolves.toBe(true);

    expect(parseMock).toHaveBeenCalledWith(rawDocument);
    expect(persistMock).toHaveBeenCalledWith(
      { tenantId: "tenant-a", ingestionJobId: "507f1f77bcf86cd799439011" },
      { $setOnInsert: expect.objectContaining({ ...parsed, source: "ci://test", tenantId: "tenant-a", ingestionStatus: "validated" }) },
      expect.objectContaining({ upsert: true, new: true })
    );
    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({
        $set: expect.objectContaining({ status: "completed", sbomId: "sbom-1" }),
        $unset: expect.objectContaining({ rawDocument: 1 })
      })
    );
  });

  it("requeues transient persistence failures with a bounded retry delay", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob()) });
    persistMock.mockReturnValue({ lean: vi.fn().mockRejectedValue(new Error("temporary database outage")) });

    await expect(processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"))).resolves.toBe(true);

    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({
        $set: expect.objectContaining({ status: "queued", lastError: "SBOM persistence failed; retry scheduled.", availableAt: new Date("2026-11-24T12:00:01Z") })
      })
    );
  });

  it("marks a job failed after the final persistence attempt", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob({ attempts: 3 })) });
    persistMock.mockReturnValue({ lean: vi.fn().mockRejectedValue(new Error("permanent database failure")) });

    await processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"));

    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({ $set: expect.objectContaining({ status: "failed", lastError: "SBOM persistence failed after the maximum retry count." }) })
    );
  });

  it("fails invalid SBOM documents without retrying and deletes the raw document", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob()) });
    parseMock.mockImplementation(() => { throw new SbomValidationError("invalid schema"); });

    await expect(processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"))).resolves.toBe(true);

    expect(persistMock).not.toHaveBeenCalled();
    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({
        $set: expect.objectContaining({ status: "failed", lastError: "SBOM document failed official schema validation or normalization." }),
        $unset: expect.objectContaining({ rawDocument: 1 })
      })
    );
  });

  it("returns false when no queued or expired lease job is available", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(null) });
    await expect(processNextSbomIngestionJob()).resolves.toBe(false);
    expect(persistMock).not.toHaveBeenCalled();
  });
});
