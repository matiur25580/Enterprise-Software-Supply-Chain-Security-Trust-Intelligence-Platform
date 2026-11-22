import { connectDatabase, disconnectDatabase } from "../config/database.js";
import { AuditEvent, IdentitySession, Membership, Organization, User } from "../models/identity.js";
import { Project } from "../models/project.js";
import { logger } from "../lib/logger.js";

async function migrate(): Promise<void> {
  await connectDatabase();
  try {
    await Promise.all([
      User.createIndexes(), Organization.createIndexes(), Membership.createIndexes(),
      IdentitySession.createIndexes(), AuditEvent.createIndexes(), Project.createIndexes()
    ]);
    logger.info("Identity and project registry indexes created or verified");
  } finally { await disconnectDatabase(); }
}

migrate().catch((error: unknown) => {
  logger.fatal({ err: error }, "Database index migration failed");
  process.exitCode = 1;
});
