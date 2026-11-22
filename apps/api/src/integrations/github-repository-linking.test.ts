import test from "node:test";
import assert from "node:assert/strict";
import {linkRepositorySchema,repositoryBelongsToInstallation} from "./github-repository-linking.js";
test("repository linking accepts only explicit positive provider identifiers",()=>{
 assert.deepEqual(linkRepositorySchema.parse({installationId:12,repositoryId:34}),{installationId:12,repositoryId:34});
 assert.equal(linkRepositorySchema.safeParse({installationId:12,repositoryId:34,organizationId:"attacker"}).success,false);
 assert.equal(linkRepositorySchema.safeParse({installationId:0,repositoryId:34}).success,false);
 assert.equal(linkRepositorySchema.safeParse({installationId:12,repositoryId:"34"}).success,false);
});
test("a repository can only be selected from the verified installation inventory",()=>{
 const repositories=[{id:34},{id:56}];
 assert.equal(repositoryBelongsToInstallation({requestedRepositoryId:34,repositories}),true);
 assert.equal(repositoryBelongsToInstallation({requestedRepositoryId:99,repositories}),false);
});

import {installationWebhookTransition} from "./github-installation-webhook.js";
test("installation webhooks cannot activate an installation before provider verification",()=>{
 assert.equal(installationWebhookTransition("suspended",null,"unsuspend"),null);
 assert.equal(installationWebhookTransition("suspended",new Date(),"unsuspend"),"active");
 assert.equal(installationWebhookTransition("active",new Date(),"suspend"),"suspended");
 assert.equal(installationWebhookTransition("pending_verification",null,"deleted"),"removed");
 assert.equal(installationWebhookTransition("removed",new Date(),"unsuspend"),null);
});
