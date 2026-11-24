#!/usr/bin/env node
import fs from "node:fs";
import process from "node:process";
import { verifySignedReleasePassport, type SignedReleasePassport } from "../apps/api/src/services/releasePassport";
const index = process.argv.indexOf("--file");
try {
  if (index < 0 || !process.argv[index + 1]) throw new Error("Usage: npm run passport:verify -- --file <passport.json>");
  const parsed: unknown = JSON.parse(fs.readFileSync(process.argv[index + 1], "utf8"));
  const passport: SignedReleasePassport | undefined =
    parsed && typeof parsed === "object" && "passport" in parsed
      ? (parsed as { passport?: SignedReleasePassport }).passport
      : parsed as SignedReleasePassport;
  if (!passport || !verifySignedReleasePassport(passport)) {
    process.stderr.write("INVALID: signature or payload verification failed.\n");
    process.exitCode = 2;
  } else {
    process.stdout.write(JSON.stringify({
      valid: true, keyId: passport.keyId, passportId: passport.payload.passportId,
      artifactDigest: passport.payload.artifact.sha256, policyOutcome: passport.payload.policy.outcome
    }, null, 2) + "\n");
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to verify passport");
  process.exitCode = 1;
}
