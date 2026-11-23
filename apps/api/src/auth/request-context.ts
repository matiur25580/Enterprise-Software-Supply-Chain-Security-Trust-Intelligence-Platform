import type { Request } from "express";
import type { Role } from "./roles.js";
import type { SessionClaims } from "./session.js";

declare global {
  namespace Express {
    interface Request {
      auth?: SessionClaims;
      organizationId?: string;
    }
  }
}
export type AuthenticatedRequest = Request & { auth: SessionClaims; organizationId: string; authRoles: readonly Role[] };
