import test from "node:test";
import assert from "node:assert/strict";
import { loginSchema, refreshSchema, registerSchema } from "./schemas.js";

test("registration rejects caller-supplied tenant identifiers and unknown properties", () => {
  const result = registerSchema.safeParse({
    email: "owner@example.com",
    password: "a-strong-password-123",
    displayName: "Workspace Owner",
    organizationName: "Example Workspace",
    organizationSlug: "example-workspace",
    organizationId: "attacker-selected-tenant"
  });
  assert.equal(result.success, false);
});

test("login requires a normalized organization slug and bounded credential input", () => {
  assert.equal(loginSchema.safeParse({
    email: "OWNER@example.com", password: "valid-password", organizationSlug: "example-org"
  }).success, true);
  assert.equal(loginSchema.safeParse({
    email: "owner@example.com", password: "valid-password", organizationSlug: "../other"
  }).success, false);
});

test("refresh endpoint accepts only an opaque refresh token", () => {
  assert.equal(refreshSchema.safeParse({ refreshToken: "x".repeat(64) }).success, true);
  assert.equal(refreshSchema.safeParse({ refreshToken: "x", organizationId: "other" }).success, false);
});
