#!/usr/bin/env node
import process from "node:process";

function readFlag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main(): Promise<void> {
  const sbomId = readFlag("--sbom-id");
  const artifactDigest = readFlag("--artifact-sha256");
  const token = process.env.CHAINPROOF_TOKEN;
  const baseUrl = (process.env.CHAINPROOF_API_URL || "http://localhost:4000").replace(/\/$/, "");
  if (!sbomId || !/^[a-f0-9]{24}$/i.test(sbomId) || !artifactDigest || !/^[a-f0-9]{64}$/i.test(artifactDigest)) {
    throw new Error("Usage: npm run policy:evaluate -- --sbom-id <24-char-id> --artifact-sha256 <64-char-sha256>");
  }
  if (!token) throw new Error("Set CHAINPROOF_TOKEN to a valid API bearer token; do not put tokens in command arguments.");
  const response = await fetch(`${baseUrl}/api/policy/evaluate-release`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ sbomId, artifactDigest })
  });
  const payload = await response.json().catch(() => ({ error: "API returned a non-JSON response" }));
  process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
  if (!response.ok) process.exitCode = 1;
  else if (payload && typeof payload === "object" && "outcome" in payload && payload.outcome === "block") process.exitCode = 2;
}
main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "Release policy evaluation failed");
  process.exitCode = 1;
});
