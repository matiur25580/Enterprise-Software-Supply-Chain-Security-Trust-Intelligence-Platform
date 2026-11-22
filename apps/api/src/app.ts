import cors from "cors";
import express, { type ErrorRequestHandler, type Express } from "express";
import helmet from "helmet";
import { pinoHttp } from "pino-http";
import { env } from "./config/env.js";
import { logger } from "./lib/logger.js";
import { accessRouter } from "./routes/access.js";
import { authRouter } from "./routes/auth.js";
import { projectsRouter } from "./routes/projects.js";
import { githubWebhooksRouter } from "./routes/github-webhooks.js";
import { githubInstallationsRouter } from "./routes/github-installations.js";
import { sbomsRouter } from "./routes/sboms.js";

export const app: Express = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin: env.WEB_ORIGIN,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
}));
app.use("/api/v1/webhooks", githubWebhooksRouter);
app.use("/api/v1/integrations/github", githubInstallationsRouter);
app.use("/api/v1", sbomsRouter);
app.use(express.json({ limit: "1mb", strict: true }));
app.use(pinoHttp({ logger }));

app.use("/api/v1/auth", authRouter);
app.use("/api/v1", accessRouter);
app.use("/api/v1", projectsRouter);

app.get("/api/v1/health", (_request, response) => {
  response.status(200).json({
    status: "ok",
    service: "chainproof-api",
    timestamp: new Date().toISOString()
  });
});

app.use((_request, response) => {
  response.status(404).json({ error: { code: "NOT_FOUND", message: "The requested resource was not found." } });
});

const errorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
  logger.error({ err: error }, "Unhandled request error");
  if (response.headersSent) return;
  if (error && typeof error === "object" && "type" in error && error.type === "entity.too.large") {
    response.status(413).json({ error: { code: "REQUEST_TOO_LARGE", message: "The request exceeds the configured size limit." } });
    return;
  }
  response.status(500).json({ error: { code: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred." } });
};
app.use(errorHandler);
