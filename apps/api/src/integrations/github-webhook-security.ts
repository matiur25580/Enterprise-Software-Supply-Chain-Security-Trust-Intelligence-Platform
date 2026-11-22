import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export interface GitHubWebhookMetadata {
  eventName: string;
  action: string | null;
  installationId: number | null;
  repositoryId: number | null;
  senderId: number | null;
}

export function verifyGitHubWebhookSignature(rawBody: Buffer, signature: string | undefined, secret: string): boolean {
  if (!signature || !/^sha256=[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = Buffer.from(`sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`);
  const supplied = Buffer.from(signature);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function positiveInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null;
}

export function parseGitHubWebhookMetadata(eventName: string, rawBody: Buffer): GitHubWebhookMetadata | null {
  let payload: unknown;
  try { payload = JSON.parse(rawBody.toString("utf8")); } catch { return null; }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const record = payload as Record<string, unknown>;
  const installation = record.installation && typeof record.installation === "object"
    ? record.installation as Record<string, unknown> : null;
  const repository = record.repository && typeof record.repository === "object"
    ? record.repository as Record<string, unknown> : null;
  const sender = record.sender && typeof record.sender === "object"
    ? record.sender as Record<string, unknown> : null;
  const action = typeof record.action === "string" && record.action.length <= 80 ? record.action : null;
  return {
    eventName,
    action,
    installationId: positiveInteger(installation?.id),
    repositoryId: positiveInteger(repository?.id),
    senderId: positiveInteger(sender?.id)
  };
}

export function hashGitHubWebhookPayload(rawBody: Buffer): string {
  return createHash("sha256").update(rawBody).digest("hex");
}
