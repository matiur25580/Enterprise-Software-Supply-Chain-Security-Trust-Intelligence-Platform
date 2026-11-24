import type { Request } from "express";

export type ChainProofRole = "platform-admin" | "security-analyst" | "developer" | "auditor";

export interface AuthContext {
  userId: string;
  tenantId: string;
  role: ChainProofRole;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

export type AuthenticatedRequest = Request & { auth: AuthContext };