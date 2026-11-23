import type { RequestHandler } from "express";
import { env } from "../config/env.js";
import { verifySession } from "../auth/session.js";
import type { Role } from "../auth/roles.js";
import { IdentitySession, Membership, Organization, User } from "../models/identity.js";

export const authenticate: RequestHandler = async (request, response, next) => {
  const header = request.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : undefined;
  if (!token) {
    response.status(401).json({ error: { code: "AUTHENTICATION_REQUIRED", message: "A valid bearer session is required." } });
    return;
  }
  const claims = verifySession(token, env.AUTH_SESSION_SECRET);
  if (!claims) {
    response.status(401).json({ error: { code: "INVALID_SESSION", message: "The session is invalid or expired." } });
    return;
  }
  try {
    const now = new Date();
    const [session, user, organization, membership] = await Promise.all([
      IdentitySession.findOne({
        sessionId: claims.sid, userId: claims.sub, organizationId: claims.orgId,
        revokedAt: null, expiresAt: { $gt: now }
      }),
      User.exists({ userId: claims.sub, status: "active" }),
      Organization.exists({ organizationId: claims.orgId, status: "active" }),
      Membership.findOne({ userId: claims.sub, organizationId: claims.orgId, status: "active" })
    ]);
    if (!session || !user || !organization || !membership) {
      response.status(401).json({ error: { code: "SESSION_INACTIVE", message: "The session is invalid or no longer active." } });
      return;
    }
    request.auth = { ...claims, roles: [membership.role as Role] };
    next();
  } catch (error) {
    next(error);
  }
};
