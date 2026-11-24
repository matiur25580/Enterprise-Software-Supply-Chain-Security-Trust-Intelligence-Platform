import mongoose from "mongoose";
import { connectDatabase } from "../apps/api/src/config/database";
import { SbomRecord } from "../apps/api/src/models/SbomRecord";
import { User } from "../apps/api/src/models/User";

// Run explicitly during deployment; production autoIndex is intentionally disabled.
async function main(): Promise<void> {
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is required to provision database indexes.");
  await connectDatabase();
  await Promise.all([User.createIndexes(), SbomRecord.createIndexes()]);
  console.info("ChainProof database indexes are present.");
}
main().catch((error: unknown) => {
  console.error("ChainProof index provisioning failed:", error instanceof Error ? error.message : "unknown error");
  process.exitCode = 1;
}).finally(async () => { await mongoose.disconnect(); });
