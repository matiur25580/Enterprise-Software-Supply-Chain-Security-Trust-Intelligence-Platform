import { app } from "./app.js";
import { env } from "./config/env.js";
import { logger } from "./lib/logger.js";

const server = app.listen(env.API_PORT, env.API_HOST, () => {
  logger.info({ host: env.API_HOST, port: env.API_PORT }, "ChainProof API listening");
});

const shutdown = (signal: NodeJS.Signals) => {
  logger.info({ signal }, "Shutdown signal received");
  server.close((error) => {
    if (error) {
      logger.error({ err: error }, "HTTP server shutdown failed");
      process.exitCode = 1;
    }
    process.exit();
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
