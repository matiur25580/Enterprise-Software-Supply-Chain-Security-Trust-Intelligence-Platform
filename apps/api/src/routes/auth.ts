import { Router } from "express";
import mongoose from "mongoose";
import { rateLimit } from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { User } from "../models/User";

export const authRouter = Router();

// Slow repeated password guessing without revealing whether an account exists.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many sign-in attempts; try again later." }
});

const loginSchema = z.object({
  tenantId: z.string().min(1).max(120),
  email: z.string().email().max(254),
  password: z.string().min(1).max(200)
}).strict();

authRouter.post("/login", loginLimiter, async (request, response) => {
  const parsed = loginSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: "Invalid login input" });
    return;
  }

  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    response.status(503).json({ error: "Authentication is not configured" });
    return;
  }

  try {
    const { tenantId, email, password } = parsed.data;
    const loginFilter = mongoose.sanitizeFilter({ tenantId, email: email.toLowerCase(), active: true });
    const user = await User.findOne(loginFilter).select("+passwordHash tenantId role email");

    const passwordMatches = user
      ? await bcrypt.compare(password, user.passwordHash)
      : false;

    // Use one generic response so callers cannot enumerate registered emails.
    if (!user || !passwordMatches) {
      response.status(401).json({ error: "Invalid tenant, email, or password" });
      return;
    }

    const accessToken = jwt.sign(
      { tenantId: user.tenantId, role: user.role },
      secret,
      { subject: String(user._id), algorithm: "HS256", issuer: "chainproof-api", audience: "chainproof-client", expiresIn: "15m" }
    );

    response.status(200).json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 900,
      user: { id: String(user._id), tenantId: user.tenantId, email: user.email, role: user.role }
    });
  } catch {
    response.status(500).json({ error: "Unable to complete sign-in" });
  }
});