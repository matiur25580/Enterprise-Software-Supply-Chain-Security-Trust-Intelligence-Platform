import { connectDatabase, disconnectDatabase } from "../config/database.js";
import { AuditEvent, IdentitySession, Membership, Organization, User } from "../models/identity.js";
import { logger } from "../lib/logger.js";

async function migrate(): Promise<void> {
  await connectDatabase();
  try {
    await Promise.all([
      User.createIndexes(),
      Organization.createIndexes(),
      Membership.createIndexes(),
      IdentitySession.createIndexes(),
      AuditEvent.createIndexes()
    ]);
    logger.info("Identity indexes created or verified");
  } finally {
    await disconnectDatabase();
  }
}

migrate().catch((error: unknown) => {
  logger.fatal({ err: error }, "Identity index migration failed");
  process.exitCode = 1;
});
