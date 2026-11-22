import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_HOST: z.string().default("0.0.0.0"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  API_LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
  MONGODB_URI: z.string().min(1).default("mongodb://127.0.0.1:27017/chainproof?replicaSet=rs0"),
  AUTH_SESSION_SECRET: z.string().min(32).default("chainproof-local-development-secret-change-before-deploy"),
  GITHUB_WEBHOOK_SECRET: z.preprocess((value) => value === "" ? undefined : value, z.string().min(32).optional()),
  GITHUB_APP_SLUG: z.preprocess((value) => value === "" ? undefined : value, z.string().regex(/^[A-Za-z0-9-]+$/).optional())
});

const parsed = envSchema.superRefine((value, context) => {
  if (value.NODE_ENV === "production" && value.AUTH_SESSION_SECRET === "chainproof-local-development-secret-change-before-deploy") {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["AUTH_SESSION_SECRET"], message: "A unique production session secret is required." });
  }
  if (value.NODE_ENV === "production" && /localhost|127\.0\.0\.1/.test(value.MONGODB_URI)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["MONGODB_URI"], message: "A non-local production MongoDB URI is required." });
  }
}).safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration", parsed.error.flatten().fieldErrors);
  process.exit(1);
}
export const env = Object.freeze(parsed.data);
