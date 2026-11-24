import { beforeEach, describe, expect, it, vi } from "vitest";

const { claimMock, updateJobMock, recoverMock, persistMock } = vi.hoisted(() => ({
  claimMock: vi.fn(),
  updateJobMock: vi.fn(),
  recoverMock: vi.fn(),
  persistMock: vi.fn()
}));

vi.mock("../src/models/SbomIngestionJob", () => ({
  SbomIngestionJob: {
    findOneAndUpdate: claimMock,
    updateOne: updateJobMock,
    updateMany: recoverMock
  }
}));
vi.mock("../src/models/SbomRecord", () => ({ SbomRecord: { findOneAndUpdate: persistMock } }));

import { processNextSbomIngestionJob } from "../src/services/sbomIngestionWorker";

const payload = {
  format: "cyclonedx",
  formatVersion: "1.6",
  documentName: "checkout",
  componentCount: 1,
  documentDigest: "a".repeat(64),
  normalizedComponents: [{ name: "express", purl: "pkg:npm/express@4.21.2" }],
  normalizedDependencies: []
};

function claimedJob(overrides: Record<string, unknown> = {}) {
  return {
    _id: "507f1f77bcf86cd799439011",
    tenantId: "tenant-a",
    status: "processing",
    payload,
    attempts: 1,
    maxAttempts: 3,
    ...overrides
  };
}

describe("durable SBOM ingestion worker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    recoverMock.mockResolvedValue({ modifiedCount: 0 });
    updateJobMock.mockResolvedValue({ modifiedCount: 1 });
  });

  it("claims one queued job and persists its SBOM idempotently", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob()) });
    persistMock.mockReturnValue({ lean: vi.fn().mockResolvedValue({ _id: "sbom-1" }) });

    await expect(processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"))).resolves.toBe(true);

    expect(claimMock).toHaveBeenCalledWith(
      expect.objectContaining({
        attempts: { $lt: 3 },
        $or: expect.arrayContaining([
          expect.objectContaining({ status: "queued" }),
          expect.objectContaining({ status: "processing" })
        ])
      }),
      expect.objectContaining({ $inc: { attempts: 1 }, $set: expect.objectContaining({ status: "processing" }) }),
      expect.objectContaining({ sort: { createdAt: 1 }, new: true })
    );
    expect(persistMock).toHaveBeenCalledWith(
      { tenantId: "tenant-a", ingestionJobId: "507f1f77bcf86cd799439011" },
      { $setOnInsert: expect.objectContaining({ ...payload, tenantId: "tenant-a", ingestionStatus: "validated" }) },
      expect.objectContaining({ upsert: true, new: true })
    );
    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({ $set: expect.objectContaining({ status: "completed", sbomId: "sbom-1" }) })
    );
  });

  it("requeues transient failures with a bounded retry delay", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob({ attempts: 1 })) });
    persistMock.mockReturnValue({ lean: vi.fn().mockRejectedValue(new Error("temporary database outage")) });

    await expect(processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"))).resolves.toBe(true);

    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({
        $set: expect.objectContaining({ status: "queued", lastError: "SBOM persistence failed; retry scheduled.", availableAt: new Date("2026-11-24T12:00:01Z") })
      })
    );
  });

  it("marks a job failed after the final attempt", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(claimedJob({ attempts: 3 })) });
    persistMock.mockReturnValue({ lean: vi.fn().mockRejectedValue(new Error("permanent validation conflict")) });

    await processNextSbomIngestionJob(new Date("2026-11-24T12:00:00Z"));

    expect(updateJobMock).toHaveBeenCalledWith(
      { _id: "507f1f77bcf86cd799439011", workerId: expect.stringContaining("sbom-worker-") },
      expect.objectContaining({ $set: expect.objectContaining({ status: "failed", lastError: "SBOM persistence failed after the maximum retry count." }) })
    );
  });

  it("returns false when no queued or expired lease job is available", async () => {
    claimMock.mockReturnValue({ lean: vi.fn().mockResolvedValue(null) });
    await expect(processNextSbomIngestionJob()).resolves.toBe(false);
    expect(persistMock).not.toHaveBeenCalled();
  });
});
