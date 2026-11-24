#!/usr/bin/env node
import fs from "node:fs";
import process from "node:process";
import { verifySignedReleasePassport, type SignedReleasePassport } from "../apps/api/src/services/releasePassport";

function readFileArgument(): string | undefined {
  const index = process.argv.indexOf("--file");
  return index >= 0 ? process.argv[index + 1] : undefined;
}

try {
  const file = readFileArgument();
  if (!file) throw new Error("Usage: npm run passport:verify -- --file <passport.json>");
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as { passport?: SignedReleasePassport } | SignedReleasePassport;
  const passport = "passport" in parsed ? parsed.passport : parsed;
  if (!passport || !verifySignedReleasePassport(passport)) {
    process.stderr.write("INVALID: signature, public-key fingerprint or passport payload verification failed.\n");
    process.exitCode = 2;
  } else {
    process.stdout.write(JSON.stringify({
      valid: true,
      algorithm: passport.algorithm,
      keyId: passport.keyId,
      passportId: passport.payload.passportId,
      artifactDigest: passport.payload.artifact.sha256,
      policyOutcome: passport.payload.policy.outcome
    }, null, 2) + "\n");
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to verify release passport");
  process.exitCode = 1;
}
