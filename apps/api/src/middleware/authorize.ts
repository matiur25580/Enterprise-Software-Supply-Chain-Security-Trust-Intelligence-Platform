import type { NextFunction, Request, Response } from "express";
import type { ChainProofRole } from "../types/auth";

export function authorize(...allowedRoles: ChainProofRole[]) {
  return (request: Request, response: Response, next: NextFunction): void => {
    if (!request.auth) {
      response.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!allowedRoles.includes(request.auth.role)) {
      response.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}