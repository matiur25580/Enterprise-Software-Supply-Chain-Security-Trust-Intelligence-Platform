import {Router,type Router as ExpressRouter} from "express";
import {createHash,randomUUID} from "node:crypto";
import {z} from "zod";
import {authenticate} from "../middleware/authenticate.js";
import {requireOrganizationScope} from "../middleware/organization-scope.js";
import {requirePermission} from "../middleware/authorize.js";
import {Project} from "../models/project.js";
import {Sbom} from "../models/sbom.js";
import {VulnerabilityFinding} from "../models/vulnerability-finding.js";
import {AuditEvent} from "../models/identity.js";
import {scanComponentsWithOsv,versionedPurl} from "../integrations/osv-client.js";
export const vulnerabilitiesRouter:ExpressRouter=Router();
const base="/organizations/:organizationId/projects/:projectId";
const listQuerySchema=z.object({limit:z.coerce.number().int().min(1).max(100).default(50),severity:z.enum(["critical","high","moderate","low","unknown"]).optional(),status:z.enum(["open","accepted_risk","resolved"]).optional()}).strict();
const param=(value:string|string[]|undefined):string|null=>typeof value==="string"&&value.length>0?value:null;
const componentKey=(component:{bomRef:string|null;name:string;version:string|null;purl:string|null}):string=>createHash("sha256").update([component.bomRef??"",component.name,component.version??"",component.purl??""].join("\0")).digest("hex");
vulnerabilitiesRouter.post(`${base}/sboms/:sbomId/scan`,authenticate,requireOrganizationScope,requirePermission("projects:write"),async(request,response,next)=>{
 const projectId=param(request.params.projectId),sbomId=param(request.params.sbomId);
 if(!projectId||!sbomId){response.status(404).json({error:{code:"SBOM_NOT_FOUND",message:"The SBOM was not found."}});return;}
 try{
  const organizationId=request.auth!.orgId;
  const project=await Project.findOne({organizationId,projectId,status:"active"}).select({projectId:1}).lean();
  if(!project){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The active project was not found."}});return;}
  const sbom=await Sbom.findOne({organizationId,projectId,sbomId}).lean() as unknown as {components:Array<{bomRef:string|null;name:string;version:string|null;purl:string|null}>}|null;
  if(!sbom){response.status(404).json({error:{code:"SBOM_NOT_FOUND",message:"The SBOM was not found."}});return;}
  const result=await scanComponentsWithOsv(sbom.components);
  const scannedAt=new Date();
  const componentsByPurl=new Map<string,Array<(typeof sbom.components)[number]>>();
  for(const component of sbom.components){const purl=versionedPurl(component);if(purl){const items=componentsByPurl.get(purl)??[];items.push(component);componentsByPurl.set(purl,items);}}
  const accepted=await VulnerabilityFinding.find({organizationId,projectId,sbomId,status:"accepted_risk"}).select({componentKey:1,vulnerabilityId:1}).lean();
  const acceptedKeys=new Set(accepted.map(item=>`${item.componentKey}:${item.vulnerabilityId}`));
  await VulnerabilityFinding.updateMany({organizationId,projectId,sbomId,status:"open"},{$set:{status:"resolved"}});
  const operations=result.findings.flatMap(finding=>(componentsByPurl.get(finding.packageUrl)??[]).map(component=>{
   const key=componentKey(component),isAccepted=acceptedKeys.has(`${key}:${finding.vulnerabilityId}`);
   const values={componentKey:key,componentName:component.name,componentVersion:component.version,purl:finding.packageUrl,vulnerabilityId:finding.vulnerabilityId,summary:finding.summary,details:finding.details,aliases:finding.aliases,severity:finding.severity,cvssScore:finding.cvssScore,affectedVersions:finding.affectedVersions,fixedVersions:finding.fixedVersions,references:finding.references,recommendedAction:finding.recommendedAction,source:"OSV",lastScannedAt:scannedAt};
   return {updateOne:{filter:{organizationId,projectId,sbomId,componentKey:key,vulnerabilityId:finding.vulnerabilityId},update:{$set:{...values,...(isAccepted?{}:{status:"open"})},$setOnInsert:{findingId:randomUUID(),organizationId,projectId,sbomId,...(isAccepted?{status:"open"}:{})}},upsert:true}};
  }));
  if(operations.length)await VulnerabilityFinding.bulkWrite(operations,{ordered:false});
  await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"vulnerability.scan_completed",targetType:"sbom",targetId:sbomId,metadata:{projectId,scannedPackages:result.scannedPackages,skippedPackages:result.skippedPackages,vulnerabilityCount:result.vulnerabilityCount,scannedAt}});
  const counts=await VulnerabilityFinding.aggregate([{ $match:{organizationId,projectId,sbomId,status:"open"}},{ $group:{_id:"$severity",count:{$sum:1}}}]);
  response.status(200).json({data:{sbomId,projectId,scannedPackages:result.scannedPackages,skippedPackages:result.skippedPackages,vulnerabilityCount:result.vulnerabilityCount,openFindingsBySeverity:Object.fromEntries(counts.map(item=>[item._id,item.count])),scannedAt}});
 }catch(error){next(error);}
});
vulnerabilitiesRouter.get(`${base}/vulnerabilities`,authenticate,requireOrganizationScope,requirePermission("projects:read"),async(request,response,next)=>{
 const projectId=param(request.params.projectId),parsed=listQuerySchema.safeParse(request.query);
 if(!projectId){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The project was not found."}});return;}
 if(!parsed.success){response.status(400).json({error:{code:"INVALID_QUERY",message:"The vulnerability query is invalid."}});return;}
 try{
  const organizationId=request.auth!.orgId;
  const project=await Project.findOne({organizationId,projectId}).select({projectId:1}).lean();
  if(!project){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The project was not found."}});return;}
  const filter:Record<string,unknown>={organizationId,projectId};
  if(parsed.data.severity)filter.severity=parsed.data.severity;
  if(parsed.data.status)filter.status=parsed.data.status;
  const data=await VulnerabilityFinding.find(filter).select({findingId:1,sbomId:1,componentName:1,componentVersion:1,purl:1,vulnerabilityId:1,summary:1,aliases:1,severity:1,cvssScore:1,fixedVersions:1,references:1,recommendedAction:1,status:1,lastScannedAt:1,createdAt:1}).sort({severity:1,createdAt:-1}).limit(parsed.data.limit).lean();
  response.status(200).json({data});
 }catch(error){next(error);}
});
