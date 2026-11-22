import test from "node:test";
import assert from "node:assert/strict";
import { createProjectSchema, updateProjectSchema } from "./schemas.js";
import { projectTenantFilter } from "./scope.js";

test("project creation accepts HTTPS repositories and rejects credential-bearing or non-HTTPS URLs", () => {
  const valid = createProjectSchema.safeParse({
    name: "Payments API", slug: "payments-api",
    repositoryUrl: "https://github.com/acme/payments-api"
  });
  assert.equal(valid.success, true);
  assert.equal(createProjectSchema.safeParse({
    name: "Payments API", slug: "payments-api",
    repositoryUrl: "http://github.com/acme/payments-api"
  }).success, false);
  assert.equal(createProjectSchema.safeParse({
    name: "Payments API", slug: "payments-api",
    repositoryUrl: "https://user:secret@github.com/acme/payments-api"
  }).success, false);
  assert.equal(createProjectSchema.safeParse({
    name: "Payments API", slug: "payments-api",
    repositoryUrl: "https://github.com/acme/payments-api", organizationId: "attacker-org"
  }).success, false);
});

test("project updates require at least one allowed field", () => {
  assert.equal(updateProjectSchema.safeParse({}).success, false);
  assert.equal(updateProjectSchema.safeParse({ status: "archived" }).success, true);
  assert.equal(updateProjectSchema.safeParse({ organizationId: "attacker-org" }).success, false);
});

test("project repository filters always include the authenticated organization", () => {
  assert.deepEqual(projectTenantFilter("org-a"), { organizationId: "org-a" });
  assert.deepEqual(projectTenantFilter("org-a", "project-b"), {
    organizationId: "org-a", projectId: "project-b"
  });
});
