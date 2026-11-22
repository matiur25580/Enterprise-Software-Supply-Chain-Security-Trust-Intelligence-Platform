import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,createVerify} from "node:crypto";
import {createGitHubAppJwt,GitHubAppError,validateGitHubInstallation,type VerifiedGitHubInstallation} from "./github-app-client.js";
test("GitHub App JWT is RS256 signed with bounded lifetime",()=>{
 const {privateKey,publicKey}=generateKeyPairSync("rsa",{modulusLength:2048});
 const now=1_800_000_000;
 const jwt=createGitHubAppJwt({appId:"123456",privateKey:privateKey.export({type:"pkcs8",format:"pem"}).toString(),now});
 const parts=jwt.split(".");
 assert.equal(parts.length,3);
 const header=JSON.parse(Buffer.from(parts[0]!,"base64url").toString("utf8"));
 const payload=JSON.parse(Buffer.from(parts[1]!,"base64url").toString("utf8"));
 assert.deepEqual(header,{alg:"RS256",typ:"JWT"});
 assert.deepEqual(payload,{iat:now-60,exp:now+540,iss:"123456"});
 const verifier=createVerify("RSA-SHA256");verifier.update(parts[0]+"."+parts[1]);verifier.end();
 assert.equal(verifier.verify(publicKey,Buffer.from(parts[2]!,"base64url")),true);
});

const validInstallation:VerifiedGitHubInstallation={
 id:456,app_id:123456,account:{id:789,login:"acme",type:"Organization"},
 repository_selection:"selected",permissions:{contents:"read",metadata:"read"},target_id:789
};
test("GitHub installation verification requires matching App, account and least-privilege permissions",()=>{
 assert.equal(validateGitHubInstallation(456,validInstallation,"123456"),validInstallation);
 assert.throws(()=>validateGitHubInstallation(999,validInstallation,"123456"),GitHubAppError);
 assert.throws(()=>validateGitHubInstallation(456,validInstallation,"999999"),GitHubAppError);
 assert.throws(()=>validateGitHubInstallation(456,{...validInstallation,repository_selection:"all"},"123456"),GitHubAppError);
 assert.throws(()=>validateGitHubInstallation(456,{...validInstallation,permissions:{contents:"write",metadata:"read"}},"123456"),GitHubAppError);
 assert.throws(()=>validateGitHubInstallation(456,{...validInstallation,permissions:{contents:"read",metadata:"read",administration:"write"}},"123456"),GitHubAppError);
});
