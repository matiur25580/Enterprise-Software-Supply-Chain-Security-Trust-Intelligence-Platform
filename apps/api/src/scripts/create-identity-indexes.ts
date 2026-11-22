import { connectDatabase, disconnectDatabase } from "../config/database.js";
import { AuditEvent, IdentitySession, Membership, Organization, User } from "../models/identity.js";
import { Project } from "../models/project.js";
import { GitHubWebhookDelivery } from "../models/github-webhook-delivery.js";
import { GitHubInstallState, GitHubInstallation } from "../models/github-installation.js";
import { GitHubRepositoryLink } from "../models/github-repository-link.js";
import { Sbom } from "../models/sbom.js";
import { logger } from "../lib/logger.js";

async function migrate(): Promise<void> {
  await connectDatabase();
  try {
    await Promise.all([
      User.createIndexes(), Organization.createIndexes(), Membership.createIndexes(),
      IdentitySession.createIndexes(), AuditEvent.createIndexes(), Project.createIndexes(),
      GitHubWebhookDelivery.createIndexes(), GitHubInstallState.createIndexes(),
      GitHubInstallation.createIndexes(), GitHubRepositoryLink.createIndexes(), Sbom.createIndexes()
    ]);
    logger.info("Identity, project registry, GitHub webhook, installation, repository-link and SBOM inventory indexes created or verified");
  } finally { await disconnectDatabase(); }
}

migrate().catch((error: unknown) => {
  logger.fatal({ err: error }, "Database index migration failed");
  process.exitCode = 1;
});
