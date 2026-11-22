import { Router, type Router as ExpressRouter } from "express";
import rateLimit from "express-rate-limit";
import { login, registerOrganization, revokeSession, rotateRefreshToken, IdentityError } from "../auth/identity-service.js";
import { loginSchema, refreshSchema, registerSchema } from "../auth/schemas.js";
import { authenticate } from "../middleware/authenticate.js";

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_request, response) => response.status(429).json({
    error: { code: "RATE_LIMITED", message: "Too many authentication attempts. Try again later." }
  })
});

export const authRouter: ExpressRouter = Router();
authRouter.use(limiter);

authRouter.post("/register", async (request, response, next) => {
  const parsed = registerSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: { code: "INVALID_REQUEST", message: "The request is invalid.", fields: parsed.error.flatten().fieldErrors } });
    return;
  }
  try {
    const result = await registerOrganization(parsed.data);
    response.status(201).json({ data: result });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === 11000) {
      response.status(409).json({ error: { code: "ACCOUNT_OR_ORGANIZATION_EXISTS", message: "The email address or organization identifier is already in use." } });
      return;
    }
    next(error);
  }
});

authRouter.post("/login", async (request, response, next) => {
  const parsed = loginSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: { code: "INVALID_REQUEST", message: "The request is invalid." } });
    return;
  }
  try {
    response.status(200).json({ data: await login(parsed.data) });
  } catch (error) {
    if (error instanceof IdentityError) {
      response.status(error.status).json({ error: { code: error.code, message: error.message } });
      return;
    }
    next(error);
  }
});

authRouter.post("/refresh", async (request, response, next) => {
  const parsed = refreshSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: { code: "INVALID_REQUEST", message: "The request is invalid." } });
    return;
  }
  try {
    response.status(200).json({ data: await rotateRefreshToken(parsed.data.refreshToken) });
  } catch (error) {
    if (error instanceof IdentityError) {
      response.status(error.status).json({ error: { code: error.code, message: error.message } });
      return;
    }
    next(error);
  }
});

authRouter.post("/logout", authenticate, async (request, response, next) => {
  try {
    const claims = request.auth;
    if (claims) await revokeSession({ sessionId: claims.sid, userId: claims.sub, organizationId: claims.orgId });
    response.status(204).end();
  } catch (error) { next(error); }
});
