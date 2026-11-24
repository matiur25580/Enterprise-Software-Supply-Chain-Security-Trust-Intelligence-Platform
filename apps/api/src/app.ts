import cors from "cors";
import express from "express";
import helmet from "helmet";
import { healthRouter } from "./routes/health";
import { sbomRouter } from "./routes/sbom";

export const app = express();

// Security headers are enabled by default; deployment-specific CSP policy can
// be tightened once the web application's asset and API origins are finalized.
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(",") ?? false }));
app.use(express.json({ limit: "2mb", strict: true }));

app.get("/", (_request, response) => {
  response.status(200).json({
    name: "ChainProof API",
    status: "foundation",
    message: "Software supply-chain security and trust intelligence API"
  });
});

app.use("/api/health", healthRouter);
app.use("/api/sboms", sbomRouter);

// Keep malformed JSON and unexpected errors in a consistent response shape.
// Production deployments should additionally connect structured logging and
// request correlation before enabling external traffic.
app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
  if (error instanceof SyntaxError) {
    response.status(400).json({ error: "Invalid JSON request body" });
    return;
  }

  response.status(500).json({ error: "Internal server error" });
});