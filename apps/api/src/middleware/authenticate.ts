import type { NextFunction, Request, Response } from "express";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { User } from "../models/User";
import type { ChainProofRole } from "../types/auth";

const ISSUER = "chainproof-api";
const AUDIENCE = "chainproof-client";

export async function authenticate(request: Request, response: Response, next: NextFunction): Promise<void> {
  const authorizationHeader = request.header("authorization") ?? "";
  const separator = authorizationHeader.indexOf(" ");
  const token = separator > 0 && authorizationHeader.slice(0, separator).toLowerCase() === "bearer"
    ? authorizationHeader.slice(separator + 1).trim()
    : undefined;
  const secret = process.env.JWT_SECRET;

  if (!token || !secret || secret.length < 32) {
    response.status(401).json({ error: "Authentication required" });
    return;
  }

  try {
    const claims = jwt.verify(token, secret, {
      algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE
    }) as JwtPayload;

    if (typeof claims.sub !== "string" || typeof claims.tenantId !== "string") {
      response.status(401).json({ error: "Invalid access token" });
      return;
    }

    // Re-read the account so deactivation and role changes take effect before
    // token expiry; the tenant predicate prevents cross-tenant identity reuse.
    const user = await User.findOne({
      _id: claims.sub, tenantId: claims.tenantId, active: true
    }).select("tenantId role");

    if (!user) {
      response.status(401).json({ error: "Account is inactive or unavailable" });
      return;
    }

    request.auth = {
      userId: String(user._id),
      tenantId: user.tenantId,
      role: user.role as ChainProofRole
    };
    next();
  } catch {
    response.status(401).json({ error: "Invalid or expired access token" });
  }
}