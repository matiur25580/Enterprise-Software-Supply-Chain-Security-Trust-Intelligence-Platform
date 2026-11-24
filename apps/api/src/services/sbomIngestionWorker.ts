import { randomUUID } from "node:crypto";
import { SbomIngestionJob } from "../models/SbomIngestionJob";
import { SbomRecord } from "../models/SbomRecord";
import { parseSbomDocument, SbomValidationError } from "./sbomParser";

const POLL_INTERVAL_MS = 1_000;
const LEASE_DURATION_MS = 60_000;
const RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const workerId = `sbom-worker-${process.pid}-${randomUUID()}`;
let timer: NodeJS.Timeout | undefined;
let running = false;

export async function processNextSbomIngestionJob(now = new Date()): Promise<boolean> {
  const leaseExpiredAt = new Date(now.getTime() - LEASE_DURATION_MS);
  await SbomIngestionJob.updateMany(
    { status: "processing", lockedAt: { $lte: leaseExpiredAt }, attempts: { $gte: 3 } },
    {
      $set: { status: "failed", lastError: "Worker lease expired after the maximum retry count.", completedAt: now, expiresAt: new Date(now.getTime() + RETENTION_MS) },
      $unset: { rawDocument: 1, lockedAt: 1, workerId: 1 }
    }
  );
  const job: any = await SbomIngestionJob.findOneAndUpdate(
    {
      attempts: { $lt: 3 },
      $or: [
        { status: "queued", availableAt: { $lte: now } },
        { status: "processing", lockedAt: { $lte: leaseExpiredAt } }
      ]
    },
    { $set: { status: "processing", lockedAt: now, workerId }, $inc: { attempts: 1 } },
    { sort: { createdAt: 1 }, new: true }
  ).lean();

  if (!job) return false;

  try {
    const payload = parseSbomDocument(job.rawDocument);
    const record: any = await SbomRecord.findOneAndUpdate(
      { tenantId: job.tenantId, ingestionJobId: job._id },
      {
        $setOnInsert: {
          ...payload,
          source: job.source,
          tenantId: job.tenantId,
          ingestionJobId: job._id,
          ingestionStatus: "validated"
        }
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    ).lean();

    await SbomIngestionJob.updateOne(
      { _id: job._id, workerId },
      {
        $set: { status: "completed", sbomId: record._id, completedAt: now, expiresAt: new Date(now.getTime() + RETENTION_MS) },
        $unset: { rawDocument: 1, lockedAt: 1, workerId: 1, lastError: 1 }
      }
    );
    return true;
  } catch (error) {
    const duplicateDigest = typeof error === "object" && error !== null && "code" in error && error.code === 11000;
    const invalidDocument = error instanceof SbomValidationError;
    const terminal = job.attempts >= job.maxAttempts || duplicateDigest || invalidDocument;
    const message = invalidDocument
      ? "SBOM document failed official schema validation or normalization."
      : duplicateDigest
        ? "An SBOM with this digest already exists in this tenant."
        : terminal ? "SBOM persistence failed after the maximum retry count." : "SBOM persistence failed; retry scheduled.";
    const delayMs = Math.min(30_000, 1_000 * (2 ** Math.max(0, job.attempts - 1)));
    await SbomIngestionJob.updateOne(
      { _id: job._id, workerId },
      terminal
        ? {
            $set: { status: "failed", lastError: message, completedAt: now, expiresAt: new Date(now.getTime() + RETENTION_MS) },
            $unset: { rawDocument: 1, lockedAt: 1, workerId: 1 }
          }
        : {
            $set: { status: "queued", lastError: message, availableAt: new Date(now.getTime() + delayMs) },
            $unset: { lockedAt: 1, workerId: 1 }
          }
    );
    return true;
  }
}

export function startSbomIngestionWorker(): void {
  if (timer) return;
  timer = setInterval(() => {
    if (running) return;
    running = true;
    void processNextSbomIngestionJob()
      .catch((error: unknown) => console.error("SBOM ingestion worker poll failed:", error instanceof Error ? error.message : "unknown error"))
      .finally(() => { running = false; });
  }, POLL_INTERVAL_MS);
  timer.unref();
}
