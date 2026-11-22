import {randomUUID} from "node:crypto";
import {GitHubInstallation} from "../models/github-installation.js";
import {GitHubRepositoryLink} from "../models/github-repository-link.js";
import {AuditEvent} from "../models/identity.js";
export type InstallationStatus="pending_verification"|"active"|"suspended"|"removed";
export function installationWebhookTransition(current:InstallationStatus,verifiedAt:Date|null,action:string|null):InstallationStatus|null{
 if(action==="deleted")return "removed";
 if(action==="suspend")return current==="removed"?null:"suspended";
 if(action==="unsuspend")return verifiedAt&&current==="suspended"?"active":null;
 return null;
}
export async function applyGitHubInstallationWebhook(input:{eventName:string;action:string|null;installationId:number|null}):Promise<"ignored"|"updated">{
 if(input.eventName!=="installation"||!input.installationId)return "ignored";
 const installation=await GitHubInstallation.findOne({installationId:input.installationId});
 if(!installation)return "ignored";
 const nextStatus=installationWebhookTransition(installation.status as InstallationStatus,installation.verifiedAt,input.action);
 if(!nextStatus)return "ignored";
 const previousStatus=installation.status;
 const updated=await GitHubInstallation.findOneAndUpdate(
  {installationId:input.installationId,status:previousStatus},
  {$set:{status:nextStatus}},
  {new:true}
 );
 if(!updated)return "ignored";
 await GitHubRepositoryLink.updateMany(
  {installationId:input.installationId,status:{$ne:"removed"}},
  {$set:{status:nextStatus}}
 );
 await AuditEvent.create({
  eventId:randomUUID(),organizationId:installation.organizationId,actorUserId:"github-app",
  action:`integration.github_installation_${input.action}`,targetType:"github_installation",
  targetId:String(input.installationId),metadata:{previousStatus,nextStatus,eventSource:"verified_github_webhook"}
 });
 return "updated";
}
