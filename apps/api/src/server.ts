import { app } from "./app";
import { connectDatabase, isDatabaseConnected } from "./config/database";
import { startSbomIngestionWorker } from "./services/sbomIngestionWorker";

const port = Number(process.env.PORT ?? 4000);
const host = process.env.HOST ?? "0.0.0.0";

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535");
}

async function start(): Promise<void> {
  // A missing URI keeps documentation/demo workflows runnable without a DB.
  // If a URI is supplied but the database is unavailable, fail closed instead
  // of starting an API that operators may assume is fully connected.
  await connectDatabase();
  if (isDatabaseConnected()) startSbomIngestionWorker();
  app.listen(port, host, () => {
    console.info(`ChainProof API listening on ${host}:${port}`);
  });
}

void start().catch((error: unknown) => {
  console.error("ChainProof API startup failed:", error instanceof Error ? error.message : "unknown error");
  process.exitCode = 1;
});