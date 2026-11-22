import { createHash, randomBytes } from "node:crypto";

export function createRefreshToken(): string {
  return randomBytes(48).toString("base64url");
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function classifyRefreshToken(hash: string, currentHash: string | null, previousHashes: readonly string[]): "current" | "replay" | "invalid" {
  if (currentHash === hash) return "current";
  if (previousHashes.includes(hash)) return "replay";
  return "invalid";
}
