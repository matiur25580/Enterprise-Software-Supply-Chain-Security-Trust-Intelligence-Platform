import test from "node:test";
import assert from "node:assert/strict";
import { parseEnvironment } from "./env.js";

const productionBase = {
  NODE_ENV: "production",
  MONGODB_URI: "mongodb+srv://db.example.com/chainproof"
};

test("production rejects a missing session secret", () => {
  const result = parseEnvironment(productionBase);
  assert.equal(result.success, false);
  if (!result.success) {
    assert.ok(result.error.flatten().fieldErrors.AUTH_SESSION_SECRET);
  }
});

test("production rejects the committed .env.example placeholder", () => {
  const result = parseEnvironment({
    ...productionBase,
    AUTH_SESSION_SECRET: "local-development-only-secret-do-not-use-in-production"
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

test("production accepts a 32-byte random base64url secret", () => {
  const result = parseEnvironment({
    ...productionBase,
    AUTH_SESSION_SECRET: "A".repeat(43)
  });
  assert.equal(result.success, true);
});

test("development retains its local default secret", () => {
  const result = parseEnvironment({ NODE_ENV: "development" });
  assert.equal(result.success, true);
});
