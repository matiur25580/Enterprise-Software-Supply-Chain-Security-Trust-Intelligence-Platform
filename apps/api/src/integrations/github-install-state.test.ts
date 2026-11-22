import test from "node:test";
import assert from "node:assert/strict";
import {createGitHubInstallState,verifyGitHubInstallState} from "./github-install-state.js";
const secret="chainproof-test-secret-at-least-thirty-two-characters";
const organizationId="a4d7e6a8-9e57-4a44-94b5-81a7bfc5aeb1";
const userId="b4d7e6a8-9e57-4a44-94b5-81a7bfc5aeb2";
test("GitHub installation state is signed, scoped and expires",()=>{
 const created=createGitHubInstallState({organizationId,userId,secret,now:1000,ttlSeconds:600});
 assert.deepEqual(verifyGitHubInstallState(created.state,secret,1100),{organizationId,userId,nonce:created.nonce,expiresAt:1600});
 assert.equal(verifyGitHubInstallState(created.state, "wrong-secret",1100),null);
 assert.equal(verifyGitHubInstallState(created.state,secret,1600),null);
 assert.equal(verifyGitHubInstallState(created.state+".tampered",secret,1100),null);
});
test("GitHub installation state rejects expired and malformed values",()=>{
 assert.equal(verifyGitHubInstallState("not-a-state",secret),null);
 const created=createGitHubInstallState({organizationId,userId,secret,now:1000,ttlSeconds:600});
 assert.equal(verifyGitHubInstallState(created.state,secret,2000),null);
});
