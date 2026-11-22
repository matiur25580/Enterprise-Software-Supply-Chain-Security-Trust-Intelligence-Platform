import test from "node:test";
import assert from "node:assert/strict";
import { organizationScopeMatches } from "../middleware/organization-scope.js";

test("tenant scope accepts only the authenticated membership organization", () => {
  const authenticatedOrganization = "f07b74f5-5c95-4eaa-9f15-08f9d6df9a01";
  const otherOrganization = "9f9c5a14-ccad-4c99-9d39-0f3d4b8e2a02";
  assert.equal(organizationScopeMatches(authenticatedOrganization, authenticatedOrganization), true);
  assert.equal(organizationScopeMatches(authenticatedOrganization, otherOrganization), false);
  assert.equal(organizationScopeMatches(authenticatedOrganization, undefined), false);
});

test("tenant scope never treats a missing client organization as an implicit tenant", () => {
  assert.equal(organizationScopeMatches("f07b74f5-5c95-4eaa-9f15-08f9d6df9a01", undefined), false);
});
