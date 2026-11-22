import {randomUUID} from "node:crypto";
import {GitHubInstallation} from "../models/github-installation.js";
import {GitHubRepositoryLink} from "../models/github-repository-link.js";
import {AuditEvent} from "../models/identity.js";
export async function applyGitHubInstallationWebhook(input:{eventName:string;action:string|null;installationId:number|null}):Promise<"ignored"|"updated">{
 if(input.eventName!=="installation"||!input.installationId||!["suspend","unsuspend","deleted"].includes(input.action??""))return "ignored";
 const installation=await GitHubInstallation.findOne({installationId:input.installationId});
 if(!installation)return "ignored";
 const nextStatus=input.action==="suspend"?"suspended":input.action==="deleted"?"removed":"active";
 const previousStatus=installation.status;
 if(input.action==="unsuspend"&&!installation.verifiedAt)return "ignored";
 if(previousStatus==="removed"&&nextStatus!=="removed")return "ignored";
 const updated=await GitHubInstallation.findOneAndUpdate(
  {installationId:input.installationId,status:previousStatus},
  {$set:{status:nextStatus}},
  {new:true}
 );
 if(!updated)return "ignored";
 await GitHubRepositoryLink.updateMany(
  {installationId:input.installationId,status:{$ne:"removed"}},
  {$set:{status:nextStatus==="active"?"active":nextStatus}}
 );
 await AuditEvent.create({
  eventId:randomUUID(),organizationId:installation.organizationId,actorUserId:"github-app",
  action:`integration.github_installation_${input.action}`,targetType:"github_installation",
  targetId:String(input.installationId),metadata:{previousStatus,nextStatus,eventSource:"verified_github_webhook"}
 });
 return "updated";
}
