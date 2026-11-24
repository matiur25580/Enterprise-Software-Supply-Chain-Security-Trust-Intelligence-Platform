#!/usr/bin/env node
import fs from "node:fs";
import process from "node:process";
import { verifySignedReleasePassport, type SignedReleasePassport } from "../apps/api/src/services/releasePassport";

type TrustStatus = "active" | "retired" | "revoked";
interface TrustStore {
  schemaVersion: "chainproof.release-passport-trust-store/v1";
  keys: Array<{ keyId: string; status: TrustStatus }>;
}

function readTrustStore(file: string): TrustStore {
  const value: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!value || typeof value !== "object") throw new Error("Trust store must be a JSON object.");
  const store = value as Record<string, unknown>;
  if (store.schemaVersion !== "chainproof.release-passport-trust-store/v1" || !Array.isArray(store.keys)) {
    throw new Error("Unsupported trust-store schema. Expected chainproof.release-passport-trust-store/v1.");
  }
  const seen = new Set<string>();
  const keys = store.keys.map((entry): { keyId: string; status: TrustStatus } => {
    if (!entry || typeof entry !== "object") throw new Error("Trust-store entries must be objects.");
    const item = entry as Record<string, unknown>;
    if (typeof item.keyId !== "string" || !/^[a-f0-9]{64}$/.test(item.keyId)
      || !["active", "retired", "revoked"].includes(String(item.status))) {
      throw new Error("Each trust-store entry needs a 64-character lowercase keyId and a valid status.");
    }
    if (seen.has(item.keyId)) throw new Error("Trust store contains a duplicate keyId.");
    seen.add(item.keyId);
    return { keyId: item.keyId, status: item.status as TrustStatus };
  });
  return { schemaVersion: "chainproof.release-passport-trust-store/v1", keys };
}

const fileIndex = process.argv.indexOf("--file");
const trustIndex = process.argv.indexOf("--trust-store");
const requireTrusted = process.argv.includes("--require-trusted");

try {
  if (fileIndex < 0 || !process.argv[fileIndex + 1]) {
    throw new Error("Usage: npm run passport:verify -- --file <passport.json> [--trust-store <trust-store.json>] [--require-trusted]");
  }
  if (requireTrusted && (trustIndex < 0 || !process.argv[trustIndex + 1])) {
    throw new Error("--require-trusted requires --trust-store <trust-store.json>.");
  }

  const parsed: unknown = JSON.parse(fs.readFileSync(process.argv[fileIndex + 1], "utf8"));
  const passport: SignedReleasePassport | undefined =
    parsed && typeof parsed === "object" && "passport" in parsed
      ? (parsed as { passport?: SignedReleasePassport }).passport
      : parsed as SignedReleasePassport;

  if (!passport || !verifySignedReleasePassport(passport)) {
    process.stderr.write("INVALID: signature or payload verification failed.\\n");
    process.exitCode = 2;
  } else {
    let trustStatus: TrustStatus | "unregistered" | "not_checked" = "not_checked";
    if (trustIndex >= 0 && process.argv[trustIndex + 1]) {
      const store = readTrustStore(process.argv[trustIndex + 1]);
      trustStatus = store.keys.find((entry) => entry.keyId === passport.keyId)?.status ?? "unregistered";
      if (trustStatus === "revoked" || trustStatus === "unregistered") {
        process.stderr.write(`UNTRUSTED: signer is ${trustStatus} in the supplied trust store.\\n`);
        process.exitCode = 3;
      }
    }
    if (process.exitCode !== 3) {
      process.stdout.write(JSON.stringify({
        valid: true, trustStatus, keyId: passport.keyId, passportId: passport.payload.passportId,
        artifactDigest: passport.payload.artifact.sha256, policyOutcome: passport.payload.policy.outcome
      }, null, 2) + "\\n");
      if (requireTrusted && trustStatus !== "active" && trustStatus !== "retired") {
        process.stderr.write("UNTRUSTED: a registered active or retired signer is required.\\n");
        process.exitCode = 3;
      }
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to verify passport");
  process.exitCode = 1;
}
