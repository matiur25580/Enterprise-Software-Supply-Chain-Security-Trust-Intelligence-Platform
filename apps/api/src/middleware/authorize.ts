import type { RequestHandler } from "express";
import { hasPermission, type Permission } from "../auth/roles.js";

export function requirePermission(permission: Permission): RequestHandler {
  return (request, response, next) => {
    if (!request.auth) {
      response.status(401).json({ error: { code: "AUTHENTICATION_REQUIRED", message: "Authentication is required." } });
      return;
    }
    if (!hasPermission(request.auth.roles, permission)) {
      response.status(403).json({ error: { code: "FORBIDDEN", message: "You do not have permission to perform this action." } });
      return;
    }
    next();
  };
}
