import test from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword } from "./password.js";

test("password hashes are salted and verified", async () => {
  const first = await hashPassword("a-strong-password-123");
  const second = await hashPassword("a-strong-password-123");
  assert.notEqual(first, second);
  assert.equal(await verifyPassword("a-strong-password-123", first), true);
  assert.equal(await verifyPassword("incorrect-password-123", first), false);
});

test("password policy rejects short values", async () => {
  await assert.rejects(() => hashPassword("short"));
});
