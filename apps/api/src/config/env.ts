import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_HOST: z.string().default("0.0.0.0"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  API_LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
  AUTH_SESSION_SECRET: z.string().min(32).default("chainproof-local-development-secret-change-before-deploy")
});

const parsed = envSchema.superRefine((value, context) => {
  if (value.NODE_ENV === "production" && value.AUTH_SESSION_SECRET === "chainproof-local-development-secret-change-before-deploy") {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["AUTH_SESSION_SECRET"], message: "A unique production session secret is required." });
  }
}).safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration", parsed.error.flatten().fieldErrors);
  process.exit(1);
}
export const env = Object.freeze(parsed.data);
