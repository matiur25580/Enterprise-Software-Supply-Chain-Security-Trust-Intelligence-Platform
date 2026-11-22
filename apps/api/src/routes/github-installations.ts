import {randomUUID} from "node:crypto";
import {Router,type Router as ExpressRouter} from "express";
import type {Request,Response,NextFunction} from "express";
import {env} from "../config/env.js";
import {authenticate} from "../middleware/authenticate.js";
import {requireOrganizationScope} from "../middleware/organization-scope.js";
import {requirePermission} from "../middleware/authorize.js";
import {GitHubInstallState,GitHubInstallation} from "../models/github-installation.js";
import {Membership,Organization,User,AuditEvent} from "../models/identity.js";
import {createGitHubInstallState,verifyGitHubInstallState} from "../integrations/github-install-state.js";
export const githubInstallationsRouter:ExpressRouter=Router();
githubInstallationsRouter.post("/organizations/:organizationId/installations/start",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  if(!env.GITHUB_APP_SLUG){response.status(503).json({error:{code:"GITHUB_APP_NOT_CONFIGURED",message:"GitHub App installation is not configured."}});return;}
  try{
   const created=createGitHubInstallState({organizationId:request.auth!.orgId,userId:request.auth!.sub,secret:env.AUTH_SESSION_SECRET});
   await GitHubInstallState.create({nonce:created.nonce,organizationId:request.auth!.orgId,userId:request.auth!.sub,expiresAt:created.expiresAt});
   const installUrl=new URL(`https://github.com/apps/${env.GITHUB_APP_SLUG}/installations/new`);
   installUrl.searchParams.set("state",created.state);
   response.status(200).json({data:{installUrl:installUrl.toString(),expiresAt:created.expiresAt.toISOString()}});
  }catch(error){next(error);}
 }
);
githubInstallationsRouter.get("/callback",
 async(request:Request,response:Response,next:NextFunction)=>{
  const state=typeof request.query.state==="string"?request.query.state:"";
  const installationIdRaw=typeof request.query.installation_id==="string"?request.query.installation_id:"";
  const installationId=Number(installationIdRaw);
  const verified=verifyGitHubInstallState(state,env.AUTH_SESSION_SECRET);
  if(!verified||!Number.isSafeInteger(installationId)||installationId<=0){
   response.status(400).json({error:{code:"INVALID_INSTALLATION_CALLBACK",message:"The GitHub installation callback is invalid or expired."}});return;
  }
  try{
   const consumed=await GitHubInstallState.findOneAndDelete({nonce:verified.nonce,organizationId:verified.organizationId,userId:verified.userId,expiresAt:{$gt:new Date()}});
   if(!consumed){response.status(409).json({error:{code:"INSTALLATION_STATE_REPLAYED",message:"The installation state has expired or was already used."}});return;}
   const [user,organization,membership]=await Promise.all([
    User.exists({userId:verified.userId,status:"active"}),
    Organization.exists({organizationId:verified.organizationId,status:"active"}),
    Membership.exists({userId:verified.userId,organizationId:verified.organizationId,status:"active",role:{$in:["org_owner","org_admin"]}})
   ]);
   if(!user||!organization||!membership){response.status(403).json({error:{code:"INSTALLATION_ACTOR_INACTIVE",message:"The organization administrator is no longer authorized."}});return;}
   await GitHubInstallation.create({installationId,organizationId:verified.organizationId,status:"pending_verification",connectedByUserId:verified.userId});
   await AuditEvent.create({eventId:randomUUID(),organizationId:verified.organizationId,actorUserId:verified.userId,action:"integration.github_installation_pending_verification",targetType:"github_installation",targetId:String(installationId),metadata:{status:"pending_verification"}});
   response.status(202).json({data:{installationId,status:"pending_verification",message:"Installation recorded. Provider verification is required before repository access is enabled."}});
  }catch(error){
   if(error&&typeof error==="object"&&"code"in error&&error.code===11000){response.status(409).json({error:{code:"INSTALLATION_ALREADY_LINKED",message:"This GitHub installation is already linked."}});return;}
   next(error);
  }
 }
);
