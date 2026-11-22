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
import {GitHubAppError,listGitHubInstallationRepositories,verifyGitHubInstallation} from "../integrations/github-app-client.js";
import {Project} from "../models/project.js";
import {GitHubRepositoryLink} from "../models/github-repository-link.js";
import {linkRepositorySchema,repositoryBelongsToInstallation} from "../integrations/github-repository-linking.js";
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
   response.status(202).json({data:{installationId,status:"pending_verification",message:"Installation recorded. Verify it with GitHub before repository access."}});
  }catch(error){
   if(error&&typeof error==="object"&&"code"in error&&error.code===11000){response.status(409).json({error:{code:"INSTALLATION_ALREADY_LINKED",message:"This GitHub installation is already linked."}});return;}
   next(error);
  }
 }
);
githubInstallationsRouter.post("/organizations/:organizationId/installations/:installationId/verify",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const installationId=Number(request.params.installationId);
  if(!Number.isSafeInteger(installationId)||installationId<=0){response.status(400).json({error:{code:"INVALID_INSTALLATION_ID",message:"The installation ID is invalid."}});return;}
  try{
   const linked=await GitHubInstallation.findOne({organizationId:request.auth!.orgId,installationId});
   if(!linked){response.status(404).json({error:{code:"INSTALLATION_NOT_FOUND",message:"The installation was not found."}});return;}
   const provider=await verifyGitHubInstallation(installationId);
   if(linked.status==="removed"||linked.status==="suspended"){response.status(409).json({error:{code:"INSTALLATION_NOT_ACTIVE",message:"The installation is not eligible for activation."}});return;}
   const verifiedAt=new Date();
   const activated=await GitHubInstallation.findOneAndUpdate(
    {organizationId:request.auth!.orgId,installationId,status:{$in:["pending_verification","active"]}},
    {$set:{accountId:provider.account.id,accountLogin:provider.account.login,accountType:provider.account.type,repositorySelection:provider.repository_selection,permissions:provider.permissions,appId:provider.app_id,status:"active",verifiedAt}},
    {new:true}
   );
   if(!activated){response.status(409).json({error:{code:"INSTALLATION_STATE_CHANGED",message:"The installation changed state during verification. Refresh and retry."}});return;}
   await AuditEvent.create({eventId:randomUUID(),organizationId:request.auth!.orgId,actorUserId:request.auth!.sub,action:"integration.github_installation_verified",targetType:"github_installation",targetId:String(installationId),metadata:{accountLogin:provider.account.login,repositorySelection:provider.repository_selection,permissions:provider.permissions}});
   response.status(200).json({data:{installationId,status:"active",account:{login:provider.account.login,type:provider.account.type},repositorySelection:provider.repository_selection,permissions:provider.permissions}});
  }catch(error){
   if(error instanceof GitHubAppError){const status=error.status===503?503:error.status===403?403:error.status===404?404:502;response.status(status).json({error:{code:"GITHUB_INSTALLATION_VERIFICATION_FAILED",message:error.message}});return;}
   next(error);
  }
 }
);
githubInstallationsRouter.get("/organizations/:organizationId/installations/:installationId/repositories",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const installationId=Number(request.params.installationId);
  if(!Number.isSafeInteger(installationId)||installationId<=0){response.status(400).json({error:{code:"INVALID_INSTALLATION_ID",message:"The installation ID is invalid."}});return;}
  try{
   const linked=await GitHubInstallation.findOne({organizationId:request.auth!.orgId,installationId,status:"active"});
   if(!linked){response.status(404).json({error:{code:"VERIFIED_INSTALLATION_NOT_FOUND",message:"A verified installation was not found."}});return;}
   const result=await listGitHubInstallationRepositories(installationId);
   response.status(200).json({data:{repositories:result.repositories,totalCount:result.totalCount,hasMore:result.hasMore}});
  }catch(error){
   if(error instanceof GitHubAppError){const status=error.status===503?503:error.status===403?403:error.status===404?404:502;response.status(status).json({error:{code:"GITHUB_REPOSITORY_DISCOVERY_FAILED",message:error.message}});return;}
   next(error);
  }
 }
);

githubInstallationsRouter.get("/organizations/:organizationId/projects/:projectId/repositories",
 authenticate,requireOrganizationScope,requirePermission("projects:read"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const projectId=typeof request.params.projectId==="string"?request.params.projectId:"";
  try{
   const project=await Project.findOne({organizationId:request.auth!.orgId,projectId}).lean();
   if(!project){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The project was not found."}});return;}
   const links=await GitHubRepositoryLink.find({organizationId:request.auth!.orgId,projectId,status:{$ne:"removed"}}).sort({fullName:1}).lean();
   response.status(200).json({data:links});
  }catch(error){next(error);}
 }
);
githubInstallationsRouter.post("/organizations/:organizationId/projects/:projectId/repositories",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const projectId=typeof request.params.projectId==="string"?request.params.projectId:"";
  const parsed=linkRepositorySchema.safeParse(request.body);
  if(!parsed.success){response.status(400).json({error:{code:"INVALID_REPOSITORY_LINK",message:"A valid installation and repository ID are required."}});return;}
  try{
   const organizationId=request.auth!.orgId;
   const project=await Project.findOne({organizationId,projectId,status:"active"}).lean();
   if(!project){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The active project was not found."}});return;}
   const installation=await GitHubInstallation.findOne({organizationId,installationId:parsed.data.installationId,status:"active"});
   if(!installation){response.status(404).json({error:{code:"VERIFIED_INSTALLATION_NOT_FOUND",message:"A verified installation was not found for this organization."}});return;}
   const inventory=await listGitHubInstallationRepositories(parsed.data.installationId);
   if(!repositoryBelongsToInstallation({requestedRepositoryId:parsed.data.repositoryId,repositories:inventory.repositories})){
    response.status(404).json({error:{code:"REPOSITORY_NOT_INSTALLED",message:"The repository is not available through this verified installation."}});return;
   }
   const providerRepository=inventory.repositories.find(item=>item.id===parsed.data.repositoryId)!;
   const ownerLogin=providerRepository.full_name.split("/")[0]??"";
   const existing=await GitHubRepositoryLink.findOne({organizationId,repositoryId:providerRepository.id});
   if(existing&&existing.status!=="removed"&&existing.projectId!==projectId){
    response.status(409).json({error:{code:"REPOSITORY_ALREADY_LINKED",message:"This repository is already linked to another project in this organization."}});return;
   }
   const linked=await GitHubRepositoryLink.findOneAndUpdate(
    {organizationId,repositoryId:providerRepository.id},
    {$set:{projectId,installationId:parsed.data.installationId,ownerLogin,name:providerRepository.name,fullName:providerRepository.full_name,htmlUrl:providerRepository.html_url,defaultBranch:providerRepository.default_branch,isPrivate:providerRepository.private,status:"active",linkedByUserId:request.auth!.sub}},
    {new:true,upsert:true,runValidators:true,setDefaultsOnInsert:true}
   );
   await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"integration.github_repository_linked",targetType:"github_repository",targetId:String(providerRepository.id),metadata:{projectId,installationId:parsed.data.installationId,fullName:providerRepository.full_name}});
   response.status(201).json({data:linked});
  }catch(error){
   if(error&&typeof error==="object"&&"code"in error&&error.code===11000){response.status(409).json({error:{code:"REPOSITORY_ALREADY_LINKED",message:"The repository is already linked."}});return;}
   if(error instanceof GitHubAppError){const status=error.status===503?503:error.status===403?403:error.status===404?404:502;response.status(status).json({error:{code:"GITHUB_REPOSITORY_LOOKUP_FAILED",message:error.message}});return;}
   next(error);
  }
 }
);
githubInstallationsRouter.delete("/organizations/:organizationId/projects/:projectId/repositories/:repositoryId",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const projectId=typeof request.params.projectId==="string"?request.params.projectId:"";
  const repositoryId=Number(request.params.repositoryId);
  if(!Number.isSafeInteger(repositoryId)||repositoryId<=0){response.status(400).json({error:{code:"INVALID_REPOSITORY_ID",message:"The repository ID is invalid."}});return;}
  try{
   const link=await GitHubRepositoryLink.findOneAndUpdate(
    {organizationId:request.auth!.orgId,projectId,repositoryId,status:{$ne:"removed"}},
    {$set:{status:"removed"}},
    {new:true}
   );
   if(!link){response.status(404).json({error:{code:"REPOSITORY_LINK_NOT_FOUND",message:"The repository link was not found."}});return;}
   await AuditEvent.create({eventId:randomUUID(),organizationId:request.auth!.orgId,actorUserId:request.auth!.sub,action:"integration.github_repository_unlinked",targetType:"github_repository",targetId:String(repositoryId),metadata:{projectId}});
   response.status(200).json({data:{repositoryId,status:"removed"}});
  }catch(error){next(error);}
 }
);
