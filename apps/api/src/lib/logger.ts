import pino from "pino";
import { env } from "../config/env.js";

export const logger = pino({
  level: env.API_LOG_LEVEL,
  redact: {
    paths: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.token", "*.secret"],
    censor: "[REDACTED]"
  },
  timestamp: pino.stdTimeFunctions.isoTime
});
