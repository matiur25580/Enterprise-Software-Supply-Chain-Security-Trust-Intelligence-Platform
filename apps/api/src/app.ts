import cors from "cors";
import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import fs from "node:fs";
import path from "node:path";
import { authenticate } from "./middleware/authenticate";
import { authRouter } from "./routes/auth";
import { healthRouter } from "./routes/health";
import { sbomRouter } from "./routes/sbom";
import { trustRouter } from "./routes/trust";
import { policyRouter } from "./routes/policy";
import { vexRouter } from "./routes/vex";
import { signerRouter } from "./routes/signers";

export const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(",") ?? false }));
app.use(express.json({ limit: "2mb", strict: true }));

// A global ceiling also protects health, static-file and fallback handlers.
const apiLimiter = rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false });

app.use("/api/health", apiLimiter, healthRouter);
app.use("/api/auth", apiLimiter, authRouter);
app.use("/api/sboms", apiLimiter, authenticate, sbomRouter);
app.use("/api/trust", apiLimiter, authenticate, trustRouter);
app.use("/api/policy", apiLimiter, authenticate, policyRouter);
app.use("/api/vex", apiLimiter, authenticate, vexRouter);
app.use("/api/policy", apiLimiter, authenticate, signerRouter);

// Serve the compiled Vite application when a web build is present.
const webDist = path.resolve(process.cwd(), "apps/web/dist");
if (fs.existsSync(webDist)) {
  app.use(apiLimiter, express.static(webDist));
  app.get("/", apiLimiter, (_request, response) => response.sendFile(path.join(webDist, "index.html")));
} else {
  app.get("/", apiLimiter, (_request, response) => response.status(200).json({
    name: "ChainProof API",
    status: "foundation",
    message: "Build the web workspace with npm run build:web to serve the dashboard."
  }));
}

app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
  if (error instanceof SyntaxError) {
    response.status(400).json({ error: "Invalid JSON request body" });
    return;
  }
  response.status(500).json({ error: "Internal server error" });
});