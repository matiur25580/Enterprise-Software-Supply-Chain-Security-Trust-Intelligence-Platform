import type { RequestHandler } from "express";

export const requireOrganizationScope: RequestHandler = (request, response, next) => {
  const claims = request.auth;
  const requestedOrganization = request.params.organizationId;
  if (!claims) {
    response.status(401).json({ error: { code: "AUTHENTICATION_REQUIRED", message: "Authentication is required." } });
    return;
  }
  if (!requestedOrganization || requestedOrganization !== claims.orgId) {
    response.status(404).json({ error: { code: "RESOURCE_NOT_FOUND", message: "The requested resource was not found." } });
    return;
  }
  request.organizationId = claims.orgId;
  next();
};
