import cors from "cors";
import express from "express";
import helmet from "helmet";
import { authenticate } from "./middleware/authenticate";
import { authorize } from "./middleware/authorize";
import { authRouter } from "./routes/auth";
import { healthRouter } from "./routes/health";
import { sbomRouter } from "./routes/sbom";

export const app = express();

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
app.use("/api/auth", authRouter);
// All SBOM operations require a current tenant account and an explicit role.
app.use("/api/sboms", authenticate, authorize("platform-admin", "security-analyst", "developer", "auditor"), sbomRouter);

app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
  if (error instanceof SyntaxError) {
    response.status(400).json({ error: "Invalid JSON request body" });
    return;
  }
  response.status(500).json({ error: "Internal server error" });
});