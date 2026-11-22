import type { RequestHandler } from "express";
export function organizationScopeMatches(authenticatedOrganizationId:string,requestedOrganizationId:string|undefined):boolean {
 return Boolean(requestedOrganizationId)&&requestedOrganizationId===authenticatedOrganizationId;
}
export const requireOrganizationScope:RequestHandler=(request,response,next)=>{
 const claims=request.auth;
 if(!claims){response.status(401).json({error:{code:"AUTHENTICATION_REQUIRED",message:"Authentication is required."}});return;}
 const requestedOrganizationId=typeof request.params.organizationId==="string"?request.params.organizationId:undefined;
 if(!organizationScopeMatches(claims.orgId,requestedOrganizationId)){response.status(404).json({error:{code:"RESOURCE_NOT_FOUND",message:"The requested resource was not found."}});return;}
 request.organizationId=claims.orgId;next();
};
