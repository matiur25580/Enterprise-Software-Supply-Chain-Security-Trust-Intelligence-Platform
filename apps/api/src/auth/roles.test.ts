import test from "node:test";
import assert from "node:assert/strict";
import { hasPermission } from "./roles.js";

test("roles grant only explicitly mapped permissions", () => {
  assert.equal(hasPermission(["security_analyst"], "findings:triage"), true);
  assert.equal(hasPermission(["viewer"], "policies:write"), false);
  assert.equal(hasPermission(["auditor"], "audit:read"), true);
  assert.equal(hasPermission(["developer"], "members:manage"), false);
});
