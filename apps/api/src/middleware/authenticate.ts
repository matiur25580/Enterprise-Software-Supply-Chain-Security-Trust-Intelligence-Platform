import type { RequestHandler } from "express";
import { env } from "../config/env.js";
import { verifySession } from "../auth/session.js";

export const authenticate: RequestHandler = (request, response, next) => {
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
  request.auth = claims;
  next();
};
