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
  GITHUB_APP_SLUG: z.preprocess((value) => value === "" ? undefined : value, z.string().regex(/^[A-Za-z0-9-]+$/).optional()),
  GITHUB_APP_ID: z.preprocess((value) => value === "" ? undefined : value, z.string().regex(/^[0-9]+$/).optional()),
  GITHUB_APP_PRIVATE_KEY: z.preprocess((value) => value === "" ? undefined : typeof value === "string" ? value.replace(/\\n/g, "\n") : value, z.string().min(100).optional()),
  CHAINPROOF_ATTESTATION_TRUSTED_KEYS: z.preprocess((value) => value === "" ? undefined : value, z.string().optional())
});

const parsed = envSchema.superRefine((value, context) => {
  if (value.NODE_ENV === "production" && value.AUTH_SESSION_SECRET === "chainproof-local-development-secret-change-before-deploy") {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["AUTH_SESSION_SECRET"], message: "A unique production session secret is required." });
  }
  if (value.NODE_ENV === "production" && /localhost|127\.0\.0\.1/.test(value.MONGODB_URI)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["MONGODB_URI"], message: "A non-local production MongoDB URI is required." });
  }
  if (value.CHAINPROOF_ATTESTATION_TRUSTED_KEYS) {
    try {
      const keys: unknown = JSON.parse(value.CHAINPROOF_ATTESTATION_TRUSTED_KEYS);
      if (!keys || typeof keys !== "object" || Array.isArray(keys) || Object.keys(keys).length > 100) throw new Error("Expected a key map with at most 100 entries.");
      for (const [keyId, entry] of Object.entries(keys)) {
        if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId) || !entry || typeof entry !== "object" ||
            (entry as Record<string, unknown>).algorithm !== "ed25519" ||
            typeof (entry as Record<string, unknown>).publicKeyPem !== "string" ||
            !String((entry as Record<string, unknown>).publicKeyPem).includes("BEGIN PUBLIC KEY")) {
          throw new Error("Each trust root needs a key ID, Ed25519 algorithm, and PEM public key.");
        }
      }
    } catch (error) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["CHAINPROOF_ATTESTATION_TRUSTED_KEYS"], message: error instanceof Error ? error.message : "Invalid attestation trust roots." });
    }
  }
  if (Boolean(value.GITHUB_APP_ID) !== Boolean(value.GITHUB_APP_PRIVATE_KEY)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["GITHUB_APP_PRIVATE_KEY"], message: "GitHub App ID and private key must be configured together." });
  }
}).safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration", parsed.error.flatten().fieldErrors);
  process.exit(1);
}
export const env = Object.freeze(parsed.data);
