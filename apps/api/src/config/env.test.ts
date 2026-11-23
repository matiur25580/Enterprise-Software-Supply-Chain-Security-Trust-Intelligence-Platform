import test from "node:test";
import assert from "node:assert/strict";
import { parseEnvironment } from "./env.js";

const productionBase: NodeJS.ProcessEnv = {
  NODE_ENV: "production",
  MONGODB_URI: "mongodb+srv://db.example.com/chainproof"
};

test("production rejects a missing session secret", () => {
  const result = parseEnvironment(productionBase);
  assert.equal(result.success, false);
  if (!result.success) assert.ok(result.error.flatten().fieldErrors.AUTH_SESSION_SECRET);
});

test("production rejects the .env.example placeholder", () => {
  const result = parseEnvironment({
    ...productionBase,
    AUTH_SESSION_SECRET: "replace-with-a-random-secret-at-least-32-characters"
  });
  assert.equal(result.success, false);
});

test("production rejects the built-in development fallback", () => {
  const result = parseEnvironment({
    ...productionBase,
    AUTH_SESSION_SECRET: "chainproof-local-development-secret-change-before-deploy"
  });
  assert.equal(result.success, false);
});

test("production accepts a 32-byte base64url secret", () => {
  const result = parseEnvironment({
    ...productionBase,
    AUTH_SESSION_SECRET: "A".repeat(43)
  });
  assert.equal(result.success, true);
});

test("production rejects loopback MongoDB hosts", () => {
  const result = parseEnvironment({
    NODE_ENV: "production",
    MONGODB_URI: "mongodb://127.0.0.1:27017/chainproof",
    AUTH_SESSION_SECRET: "A".repeat(43)
  });
  assert.equal(result.success, false);
  if (!result.success) assert.ok(result.error.flatten().fieldErrors.MONGODB_URI);
});

test("development retains its local defaults", () => {
  const result = parseEnvironment({ NODE_ENV: "development" });
  assert.equal(result.success, true);
});
