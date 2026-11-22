import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  hashGitHubWebhookPayload,
  parseGitHubWebhookMetadata,
  verifyGitHubWebhookSignature
} from "./github-webhook-security.js";

const secret = "test-webhook-secret-with-sufficient-entropy";
const body = Buffer.from(JSON.stringify({
  action: "created",
  installation: { id: 123 },
  repository: { id: 456 },
  sender: { id: 789 }
}));
const signature = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;

test("GitHub webhook signature verification accepts exact raw-body HMAC", () => {
  assert.equal(verifyGitHubWebhookSignature(body, signature, secret), true);
  assert.equal(verifyGitHubWebhookSignature(Buffer.from("{}"), signature, secret), false);
  assert.equal(verifyGitHubWebhookSignature(body, undefined, secret), false);
  assert.equal(verifyGitHubWebhookSignature(body, "sha1=bad", secret), false);
});

test("webhook metadata parser extracts only bounded provider identifiers", () => {
  assert.deepEqual(parseGitHubWebhookMetadata("installation", body), {
    eventName: "installation", action: "created",
    installationId: 123, repositoryId: 456, senderId: 789
  });
  assert.equal(parseGitHubWebhookMetadata("push", Buffer.from("not-json")), null);
  assert.equal(parseGitHubWebhookMetadata("push", Buffer.from("[]")), null);
});

test("webhook payload fingerprints are stable SHA-256 digests", () => {
  assert.equal(hashGitHubWebhookPayload(body), hashGitHubWebhookPayload(body));
  assert.match(hashGitHubWebhookPayload(body), /^[a-f0-9]{64}$/);
});
