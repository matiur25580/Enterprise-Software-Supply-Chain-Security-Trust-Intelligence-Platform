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
import {GitHubAppError,listGitHubInstallationRepositories,verifyGitHubInstallation,getGitHubRepositorySnapshot,getGitHubRepositorySbomFiles} from "../integrations/github-app-client.js";
import {Project} from "../models/project.js";
import {Sbom} from "../models/sbom.js";
import {parseSbomDocument} from "../integrations/sbom-parser.js";
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
githubInstallationsRouter.get("/organizations/:organizationId/installations",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  try{
   const installations=await GitHubInstallation.find({organizationId:request.auth!.orgId}).select("installationId accountLogin accountType repositorySelection status verifiedAt createdAt updatedAt").sort({createdAt:-1}).lean();
   response.status(200).json({data:installations});
  }catch(error){next(error);}
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
   const stillActive=await GitHubInstallation.exists({organizationId,installationId:parsed.data.installationId,status:"active"});
   if(!stillActive){
    await GitHubRepositoryLink.updateOne({_id:linked._id,status:"active"},{$set:{status:"suspended"}});
    response.status(409).json({error:{code:"INSTALLATION_STATE_CHANGED",message:"The GitHub installation changed state while linking. Refresh and retry."}});return;
   }
   await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"integration.github_repository_linked",targetType:"github_repository",targetId:String(providerRepository.id),metadata:{projectId,installationId:parsed.data.installationId,fullName:providerRepository.full_name}});
   response.status(201).json({data:linked});
  }catch(error){
   if(error&&typeof error==="object"&&"code"in error&&error.code===11000){response.status(409).json({error:{code:"REPOSITORY_ALREADY_LINKED",message:"The repository is already linked."}});return;}
   if(error instanceof GitHubAppError){const status=error.status===503?503:error.status===403?403:error.status===404?404:502;response.status(status).json({error:{code:"GITHUB_REPOSITORY_LOOKUP_FAILED",message:error.message}});return;}
   next(error);
  }
 }
);

githubInstallationsRouter.post("/organizations/:organizationId/projects/:projectId/repositories/:repositoryId/sync",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const projectId=typeof request.params.projectId==="string"?request.params.projectId:"";
  const repositoryId=Number(request.params.repositoryId);
  if(!projectId||!Number.isSafeInteger(repositoryId)||repositoryId<=0){response.status(400).json({error:{code:"INVALID_REPOSITORY_SYNC",message:"The project or repository identifier is invalid."}});return;}
  const organizationId=request.auth!.orgId;
  try{
   const [project,link]=await Promise.all([
    Project.findOne({organizationId,projectId,status:"active"}).select({projectId:1}).lean(),
    GitHubRepositoryLink.findOne({organizationId,projectId,repositoryId,status:"active"})
   ]);
   if(!project||!link){response.status(404).json({error:{code:"REPOSITORY_LINK_NOT_FOUND",message:"The active project repository link was not found."}});return;}
   const installation=await GitHubInstallation.findOne({organizationId,installationId:link.installationId,status:"active"});
   if(!installation){response.status(409).json({error:{code:"INSTALLATION_NOT_ACTIVE",message:"The linked GitHub installation is not active."}});return;}
   link.syncStatus="syncing";link.syncError=null;await link.save();
   try{
    const snapshot=await getGitHubRepositorySnapshot({installationId:link.installationId,owner:link.ownerLogin,repository:link.name});
    if(snapshot.repository.id!==repositoryId||snapshot.repository.full_name.toLowerCase()!==link.fullName.toLowerCase()){
     throw new GitHubAppError(502,"GitHub repository identity did not match the linked repository.");
    }
    const stillActive=await GitHubInstallation.exists({organizationId,installationId:link.installationId,status:"active"});
    if(!stillActive)throw new GitHubAppError(409,"The GitHub installation became inactive during synchronization.");
    link.name=snapshot.repository.name;link.fullName=snapshot.repository.full_name;link.htmlUrl=snapshot.repository.html_url;
    link.defaultBranch=snapshot.repository.default_branch;link.isPrivate=snapshot.repository.private;
    link.lastSyncedAt=new Date();link.lastSyncedCommitSha=snapshot.commit.sha;
    const commitDate=snapshot.commit.commit.committer.date||snapshot.commit.commit.author.date;
    link.lastSyncedCommitAt=commitDate?new Date(commitDate):null;
    link.syncStatus="succeeded";link.syncError=null;await link.save();
    await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"integration.github_repository_synced",targetType:"github_repository",targetId:String(repositoryId),metadata:{projectId,installationId:link.installationId,commitSha:snapshot.commit.sha,defaultBranch:snapshot.repository.default_branch}});
    response.status(200).json({data:{repositoryId,fullName:link.fullName,defaultBranch:link.defaultBranch,private:link.isPrivate,archived:snapshot.repository.archived,disabled:snapshot.repository.disabled,lastSyncedAt:link.lastSyncedAt,lastSyncedCommitSha:link.lastSyncedCommitSha,lastSyncedCommitAt:link.lastSyncedCommitAt,syncStatus:link.syncStatus}});
   }catch(error){
    link.syncStatus="failed";link.syncError=error instanceof Error?error.message.slice(0,300):"Repository synchronization failed.";await link.save();
    throw error;
   }
  }catch(error){
   if(error instanceof GitHubAppError){const status=error.status===503?503:error.status===403?403:error.status===404?404:error.status===409?409:502;response.status(status).json({error:{code:"GITHUB_REPOSITORY_SYNC_FAILED",message:error.message}});return;}
   next(error);
  }
 }
);

githubInstallationsRouter.post("/organizations/:organizationId/projects/:projectId/repositories/:repositoryId/sbom-discovery",
 authenticate,requireOrganizationScope,requirePermission("integrations:manage"),
 async(request:Request,response:Response,next:NextFunction)=>{
  const projectId=typeof request.params.projectId==="string"?request.params.projectId:"";
  const repositoryId=Number(request.params.repositoryId);
  if(!projectId||!Number.isSafeInteger(repositoryId)||repositoryId<=0){response.status(400).json({error:{code:"INVALID_SBOM_DISCOVERY",message:"The project or repository identifier is invalid."}});return;}
  const organizationId=request.auth!.orgId;
  try{
   const [project,link]=await Promise.all([
    Project.findOne({organizationId,projectId,status:"active"}).select({projectId:1}).lean(),
    GitHubRepositoryLink.findOne({organizationId,projectId,repositoryId,status:"active"})
   ]);
   if(!project||!link){response.status(404).json({error:{code:"REPOSITORY_LINK_NOT_FOUND",message:"The active project repository link was not found."}});return;}
   const installation=await GitHubInstallation.findOne({organizationId,installationId:link.installationId,status:"active"});
   if(!installation){response.status(409).json({error:{code:"INSTALLATION_NOT_ACTIVE",message:"The linked GitHub installation is not active."}});return;}
   const snapshot=await getGitHubRepositorySnapshot({installationId:link.installationId,owner:link.ownerLogin,repository:link.name});
   if(snapshot.repository.id!==repositoryId||snapshot.repository.full_name.toLowerCase()!==link.fullName.toLowerCase())throw new GitHubAppError(502,"GitHub repository identity did not match the linked repository.");
   if(snapshot.repository.archived||snapshot.repository.disabled)throw new GitHubAppError(409,"Archived or disabled repositories cannot be scanned.");
   const discovery=await getGitHubRepositorySbomFiles({installationId:link.installationId,owner:link.ownerLogin,repository:link.name,commitSha:snapshot.commit.sha});
   const stillActive=await GitHubInstallation.exists({organizationId,installationId:link.installationId,status:"active"});
   if(!stillActive)throw new GitHubAppError(409,"The GitHub installation became inactive during SBOM discovery.");
   const ingested:Array<Record<string,unknown>>=[];
   const duplicates:Array<{path:string;sbomId:string|null}>=[];
   const skipped:Array<{path:string;reason:string}>=discovery.skippedCandidates.map(item=>({...item}));
   for(const file of discovery.files){
    let parsed:ReturnType<typeof parseSbomDocument>;
    try{parsed=parseSbomDocument(file.content);}catch(error){skipped.push({path:file.path,reason:error instanceof Error?error.message:"Unsupported SBOM document."});continue;}
    const existing=await Sbom.findOne({organizationId,projectId,documentSha256:parsed.documentSha256}).select({sbomId:1}).lean();
    const existingId=existing&&!Array.isArray(existing)?(existing as {sbomId?:string}).sbomId:null;
    if(existingId){duplicates.push({path:file.path,sbomId:existingId});continue;}
    const sbomId=randomUUID();
    try{
     const document=await Sbom.create({
      sbomId,organizationId,projectId,...parsed,source:"github",sourceMetadata:{
       repositoryId,repositoryFullName:link.fullName,path:file.path,commitSha:snapshot.commit.sha
      },uploadedByUserId:request.auth!.sub
     });
     ingested.push({sbomId,format:document.format,componentCount:document.componentCount,path:file.path,documentSha256:document.documentSha256});
     await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"sbom.github_ingested",targetType:"sbom",targetId:sbomId,metadata:{projectId,repositoryId,repositoryFullName:link.fullName,path:file.path,commitSha:snapshot.commit.sha,documentSha256:parsed.documentSha256,componentCount:parsed.componentCount}});
    }catch(error){
     if(error&&typeof error==="object"&&"code"in error&&error.code===11000){
      const duplicate=await Sbom.findOne({organizationId,projectId,documentSha256:parsed.documentSha256}).select({sbomId:1}).lean();
      duplicates.push({path:file.path,sbomId:duplicate&&!Array.isArray(duplicate)?(duplicate as {sbomId?:string}).sbomId??null:null});
      continue;
     }
     throw error;
    }
   }
   link.lastSyncedAt=new Date();link.lastSyncedCommitSha=snapshot.commit.sha;
   const commitDate=snapshot.commit.commit.committer.date||snapshot.commit.commit.author.date;
   link.lastSyncedCommitAt=commitDate?new Date(commitDate):null;
   link.syncStatus="succeeded";link.syncError=null;await link.save();
   await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"integration.github_sbom_discovery_completed",targetType:"github_repository",targetId:String(repositoryId),metadata:{projectId,commitSha:snapshot.commit.sha,candidateCount:discovery.candidateCount,ingestedCount:ingested.length,duplicateCount:duplicates.length,skippedCount:skipped.length}});
   response.status(200).json({data:{repositoryId,fullName:link.fullName,commitSha:snapshot.commit.sha,candidateCount:discovery.candidateCount,downloadedCount:discovery.files.length,ingested,duplicates,skippedCount:skipped.length,skipped}});
  }catch(error){
   if(error instanceof GitHubAppError){const status=error.status===503?503:error.status===403?403:error.status===404?404:error.status===409?409:error.status===422?422:502;response.status(status).json({error:{code:"GITHUB_SBOM_DISCOVERY_FAILED",message:error.message}});return;}
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
