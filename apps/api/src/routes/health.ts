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