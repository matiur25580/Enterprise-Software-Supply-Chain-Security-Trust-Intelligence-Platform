import test from "node:test";
import assert from "node:assert/strict";
import { issueSession, verifySession } from "./session.js";

const secret = "test-session-secret-with-at-least-32-characters";

test("session token round-trips and expires", () => {
  const token = issueSession({
    userId: "4f6d5d3a-0f5b-4a90-9e0b-1b6b2d7a8c01",
    organizationId: "4f6d5d3a-0f5b-4a90-9e0b-1b6b2d7a8c02",
    roles: ["security_analyst"], secret, now: 1_700_000_000, ttlSeconds: 60
  });
  assert.equal(verifySession(token, secret, 1_700_000_030)?.roles[0], "security_analyst");
  assert.equal(verifySession(token, secret, 1_700_000_060), null);
  assert.equal(verifySession(token, "different-secret-with-at-least-32-characters", 1_700_000_030), null);
});

test("session rejects tampering and malformed tokens", () => {
  const token = issueSession({
    userId: "4f6d5d3a-0f5b-4a90-9e0b-1b6b2d7a8c01",
    organizationId: "4f6d5d3a-0f5b-4a90-9e0b-1b6b2d7a8c02",
    roles: ["viewer"], secret
  });
  const [payload, sig] = token.split(".");
  assert.equal(verifySession(payload + "x." + sig, secret), null);
  assert.equal(verifySession("not-a-token", secret), null);
});
