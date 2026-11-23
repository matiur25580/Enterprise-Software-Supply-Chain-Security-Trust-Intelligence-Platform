import "dotenv/config";
import { z } from "zod";

const DEVELOPMENT_SESSION_SECRET = "chainproof-local-development-secret-change-before-deploy";
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_HOST: z.string().default("0.0.0.0"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  API_LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
  MONGODB_URI: z.string().min(1).default("mongodb://127.0.0.1:27017/chainproof?replicaSet=rs0"),
  AUTH_SESSION_SECRET: z.string().min(32).default(DEVELOPMENT_SESSION_SECRET)
});

export function parseEnvironment(source: NodeJS.ProcessEnv = process.env) {
  return envSchema.superRefine((value, context) => {
    if (value.NODE_ENV === "production") {
      const suppliedSecret = source.AUTH_SESSION_SECRET;
      // Require a 32-byte random value encoded as unpadded base64url (43 chars).
      // This intentionally rejects all repository/example development placeholders.
      if (!suppliedSecret || !/^[A-Za-z0-9_-]{43}$/.test(suppliedSecret)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["AUTH_SESSION_SECRET"],
          message: "Production requires an explicitly supplied 32-byte random secret encoded as 43-character base64url."
        });
      }
      if (/localhost|127\\.0\\.0\\.1/.test(value.MONGODB_URI)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["MONGODB_URI"],
          message: "A non-local production MongoDB URI is required."
        });
      }
    }
  }).safeParse(source);
}

const parsed = parseEnvironment();
if (!parsed.success) {
  console.error("Invalid environment configuration", parsed.error.flatten().fieldErrors);
  process.exit(1);
}
export const env = Object.freeze(parsed.data);
