import { Router } from "express";
import { isDatabaseConnected } from "../config/database";

export const healthRouter = Router();

healthRouter.get("/", (_request, response) => {
  const database = isDatabaseConnected() ? "connected" : "not-configured";
  response.status(200).json({
    status: "ok",
    service: "chainproof-api",
    database,
    timestamp: new Date().toISOString()
  });
});
healthRouter.get("/ready", (_request, response) => {
  const ready = isDatabaseConnected();
  response.status(ready ? 200 : 503).json({
    status: ready ? "ready" : "not-ready",
    service: "chainproof-api",
    database: ready ? "connected" : "not-connected",
    timestamp: new Date().toISOString()
  });
});
