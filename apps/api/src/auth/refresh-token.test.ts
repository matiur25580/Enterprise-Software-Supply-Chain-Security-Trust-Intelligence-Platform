import test from "node:test";
import assert from "node:assert/strict";
import { classifyRefreshToken, createRefreshToken, hashRefreshToken } from "./refresh-token.js";

test("refresh credentials are high entropy and stored as one-way hashes", () => {
  const token = createRefreshToken();
  assert.equal(token.length, 64);
  assert.notEqual(hashRefreshToken(token), token);
  assert.equal(hashRefreshToken(token), hashRefreshToken(token));
  assert.match(hashRefreshToken(token), /^[a-f0-9]{64}$/);
});

test("consumed refresh token is classified as replay, not as a valid current token", () => {
  const oldHash = hashRefreshToken("a-previous-refresh-token-that-is-long-enough");
  const activeHash = hashRefreshToken("the-current-refresh-token-is-different");
  assert.equal(classifyRefreshToken(oldHash, activeHash, [oldHash]), "replay");
  assert.equal(classifyRefreshToken(activeHash, activeHash, [oldHash]), "current");
  assert.equal(classifyRefreshToken(hashRefreshToken("unknown-token-value"), activeHash, [oldHash]), "invalid");
});
