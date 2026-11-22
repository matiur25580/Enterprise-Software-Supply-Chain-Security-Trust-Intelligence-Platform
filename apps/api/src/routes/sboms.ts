import express,{Router,type Router as ExpressRouter} from "express";
import {randomUUID} from "node:crypto";
import {z} from "zod";
import {authenticate} from "../middleware/authenticate.js";
import {requireOrganizationScope} from "../middleware/organization-scope.js";
import {requirePermission} from "../middleware/authorize.js";
import {Project} from "../models/project.js";
import {Sbom} from "../models/sbom.js";
import {AuditEvent} from "../models/identity.js";
import {parseSbomDocument} from "../integrations/sbom-parser.js";
export const sbomsRouter:ExpressRouter=Router();
const base="/organizations/:organizationId/projects/:projectId/sboms";
const paramsSchema=z.object({limit:z.coerce.number().int().min(1).max(100).default(50)}).strict();
function routeParam(value:string|string[]|undefined):string|null{return typeof value==="string"&&value.length>0?value:null;}
sbomsRouter.post(base,
 authenticate,requireOrganizationScope,requirePermission("projects:write"),
 express.raw({type:"application/json",limit:"2mb"}),
 async(request,response,next)=>{
  if(!Buffer.isBuffer(request.body)){response.status(415).json({error:{code:"SBOM_CONTENT_TYPE_REQUIRED",message:"Upload a JSON SBOM with Content-Type application/json."}});return;}
  let parsed;
  try{parsed=parseSbomDocument(request.body);}catch(error){
   response.status(400).json({error:{code:"INVALID_SBOM",message:error instanceof Error?error.message:"The SBOM document is invalid."}});return;
  }
  const projectId=routeParam(request.params.projectId);
  if(!projectId){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The project was not found."}});return;}
  try{
   const organizationId=request.auth!.orgId;
   const project=await Project.findOne({organizationId,projectId,status:"active"}).lean();
   if(!project){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The active project was not found."}});return;}
   const duplicate=await Sbom.findOne({organizationId,projectId,documentSha256:parsed.documentSha256}).select({sbomId:1}).lean();
   if(duplicate){response.status(409).json({error:{code:"SBOM_ALREADY_INGESTED",message:"This exact SBOM document has already been ingested for the project.",sbomId:duplicate.sbomId}});return;}
   const sbomId=randomUUID();
   const document=await Sbom.create({sbomId,organizationId,projectId,...parsed,source:"manual",uploadedByUserId:request.auth!.sub});
   await AuditEvent.create({eventId:randomUUID(),organizationId,actorUserId:request.auth!.sub,action:"sbom.ingested",targetType:"sbom",targetId:sbomId,metadata:{projectId,format:parsed.format,specVersion:parsed.specVersion,documentSha256:parsed.documentSha256,componentCount:parsed.componentCount}});
   response.status(201).json({data:{sbomId,projectId,format:document.format,specVersion:document.specVersion,documentName:document.documentName,documentSha256:document.documentSha256,componentCount:document.componentCount,source:document.source,createdAt:document.createdAt}});
  }catch(error){
   if(error&&typeof error==="object"&&"code"in error&&error.code===11000){
    const duplicate=await Sbom.findOne({organizationId:request.auth!.orgId,projectId,documentSha256:parsed.documentSha256}).select({sbomId:1}).lean();
    response.status(409).json({error:{code:"SBOM_ALREADY_INGESTED",message:"This exact SBOM document has already been ingested for the project.",sbomId:duplicate?.sbomId??null}});return;
   }
   next(error);
  }
 }
);
sbomsRouter.get(base,
 authenticate,requireOrganizationScope,requirePermission("projects:read"),
 async(request,response,next)=>{
  const projectId=routeParam(request.params.projectId);
  const parsed=paramsSchema.safeParse(request.query);
  if(!projectId){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The project was not found."}});return;}
  if(!parsed.success){response.status(400).json({error:{code:"INVALID_QUERY",message:"The list query is invalid."}});return;}
  try{
   const organizationId=request.auth!.orgId;
   const project=await Project.findOne({organizationId,projectId}).select({projectId:1}).lean();
   if(!project){response.status(404).json({error:{code:"PROJECT_NOT_FOUND",message:"The project was not found."}});return;}
   const data=await Sbom.find({organizationId,projectId}).select({sbomId:1,format:1,specVersion:1,documentName:1,documentSha256:1,componentCount:1,source:1,createdAt:1}).sort({createdAt:-1}).limit(parsed.data.limit).lean();
   response.status(200).json({data});
  }catch(error){next(error);}
 }
);
sbomsRouter.get(`${base}/:sbomId`,
 authenticate,requireOrganizationScope,requirePermission("projects:read"),
 async(request,response,next)=>{
  const projectId=routeParam(request.params.projectId),sbomId=routeParam(request.params.sbomId);
  if(!projectId||!sbomId){response.status(404).json({error:{code:"SBOM_NOT_FOUND",message:"The SBOM was not found."}});return;}
  try{
   const document=await Sbom.findOne({organizationId:request.auth!.orgId,projectId,sbomId}).lean();
   if(!document){response.status(404).json({error:{code:"SBOM_NOT_FOUND",message:"The SBOM was not found."}});return;}
   response.status(200).json({data:document});
  }catch(error){next(error);}
 }
);
