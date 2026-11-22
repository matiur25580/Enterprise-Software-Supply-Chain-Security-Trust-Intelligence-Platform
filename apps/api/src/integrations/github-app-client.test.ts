import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,createVerify} from "node:crypto";
import {createGitHubAppJwt} from "./github-app-client.js";
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
