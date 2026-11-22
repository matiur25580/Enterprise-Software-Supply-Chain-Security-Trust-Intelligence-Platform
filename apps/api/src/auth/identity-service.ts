import { randomUUID } from "node:crypto";
import mongoose, { type ClientSession } from "mongoose";
import { hashPassword, verifyPassword } from "./password.js";
import { issueSession } from "./session.js";
import { classifyRefreshToken, createRefreshToken, hashRefreshToken } from "./refresh-token.js";
import { env } from "../config/env.js";
import { AuditEvent, IdentitySession, Membership, Organization, User } from "../models/identity.js";
import type { Role } from "./roles.js";

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const DUMMY_PASSWORD_HASH = "scrypt$16384$8$1$Y2hhaW5wcm9vZi1kdW1teQ$AahpayLC63N-6PXQyEtJqvXOJ4wy4AatX3Dlz6zmulZR2aaHyZI_UUv_yax7viE3LDqW4svmnyfjPxa317LCsA";

export class IdentityError extends Error {
  constructor(public readonly code: string, public readonly status: number, message: string) {
    super(message);
    this.name = "IdentityError";
  }
}

function issueAccessToken(userId: string, organizationId: string, sessionId: string, role: Role): string {
  return issueSession({ userId, organizationId, sessionId, roles: [role], secret: env.AUTH_SESSION_SECRET, ttlSeconds: ACCESS_TTL_SECONDS });
}

async function persistAudit(input: { organizationId: string; actorUserId: string; action: string; targetType: string; targetId?: string | null; metadata?: Record<string, unknown> }, session?: ClientSession): Promise<void> {
  await AuditEvent.create([{
    eventId: randomUUID(),
    organizationId: input.organizationId,
    actorUserId: input.actorUserId,
    action: input.action,
    targetType: input.targetType,
    targetId: input.targetId ?? null,
    metadata: input.metadata ?? {}
  }], session ? { session } : undefined);
}

export async function registerOrganization(input: { email: string; password: string; displayName: string; organizationName: string; organizationSlug: string }) {
  const userId = randomUUID();
  const organizationId = randomUUID();
  const membershipId = randomUUID();
  const sessionId = randomUUID();
  const refreshToken = createRefreshToken();
  const refreshTokenHash = hashRefreshToken(refreshToken);
  const passwordHash = await hashPassword(input.password);
  const dbSession = await mongoose.startSession();
  try {
    await dbSession.withTransaction(async () => {
      await User.create([{
        userId, email: input.email.trim().toLowerCase(), displayName: input.displayName.trim(), passwordHash
      }], { session: dbSession });
      await Organization.create([{
        organizationId, name: input.organizationName.trim(), slug: input.organizationSlug.trim().toLowerCase()
      }], { session: dbSession });
      await Membership.create([{
        membershipId, organizationId, userId, role: "org_owner", status: "active", createdByUserId: userId
      }], { session: dbSession });
      await IdentitySession.create([{
        sessionId, userId, organizationId, refreshTokenHash, previousRefreshTokenHashes: [],
        expiresAt: new Date(Date.now() + REFRESH_TTL_MS)
      }], { session: dbSession });
      await persistAudit({
        organizationId, actorUserId: userId, action: "identity.organization_registered",
        targetType: "organization", targetId: organizationId
      }, dbSession);
    });
  } finally {
    await dbSession.endSession();
  }
  return {
    user: { id: userId, email: input.email.trim().toLowerCase(), displayName: input.displayName.trim() },
    organization: { id: organizationId, name: input.organizationName.trim(), slug: input.organizationSlug.trim().toLowerCase() },
    accessToken: issueAccessToken(userId, organizationId, sessionId, "org_owner"),
    refreshToken,
    expiresIn: ACCESS_TTL_SECONDS
  };
}

export async function login(input: { email: string; password: string; organizationSlug: string }) {
  const email = input.email.trim().toLowerCase();
  const user = await User.findOne({ email }).select("+passwordHash");
  const passwordMatches = await verifyPassword(input.password, user?.passwordHash ?? DUMMY_PASSWORD_HASH);
  if (!user || !passwordMatches || user.status !== "active") {
    throw new IdentityError("INVALID_CREDENTIALS", 401, "Email or password is incorrect.");
  }
  const organization = await Organization.findOne({ slug: input.organizationSlug.trim().toLowerCase(), status: "active" });
  if (!organization) throw new IdentityError("INVALID_CREDENTIALS", 401, "Email or password is incorrect.");
  const membership = await Membership.findOne({ userId: user.userId, organizationId: organization.organizationId, status: "active" });
  if (!membership) throw new IdentityError("INVALID_CREDENTIALS", 401, "Email or password is incorrect.");

  const sessionId = randomUUID();
  const refreshToken = createRefreshToken();
  const dbSession = await mongoose.startSession();
  try {
    await dbSession.withTransaction(async () => {
      await IdentitySession.create([{
        sessionId, userId: user.userId, organizationId: organization.organizationId,
        refreshTokenHash: hashRefreshToken(refreshToken), previousRefreshTokenHashes: [],
        expiresAt: new Date(Date.now() + REFRESH_TTL_MS)
      }], { session: dbSession });
      await persistAudit({
        organizationId: organization.organizationId, actorUserId: user.userId,
        action: "identity.login_succeeded", targetType: "session", targetId: sessionId
      }, dbSession);
    });
  } finally {
    await dbSession.endSession();
  }
  return {
    user: { id: user.userId, email: user.email, displayName: user.displayName },
    organization: { id: organization.organizationId, name: organization.name, slug: organization.slug },
    accessToken: issueAccessToken(user.userId, organization.organizationId, sessionId, membership.role as Role),
    refreshToken,
    expiresIn: ACCESS_TTL_SECONDS
  };
}

export async function rotateRefreshToken(token: string) {
  const oldHash = hashRefreshToken(token);
  const current = await IdentitySession.findOne({ refreshTokenHash: oldHash }).select("+refreshTokenHash +previousRefreshTokenHashes");
  if (!current) {
    const reused = await IdentitySession.findOne({ previousRefreshTokenHashes: oldHash }).select("+previousRefreshTokenHashes");
    if (reused && !reused.revokedAt) {
      reused.revokedAt = new Date();
      await reused.save();
      await persistAudit({
        organizationId: reused.organizationId, actorUserId: reused.userId,
        action: "identity.refresh_reuse_detected", targetType: "session", targetId: reused.sessionId
      });
      throw new IdentityError("REFRESH_TOKEN_REUSE", 401, "The session has been revoked. Please sign in again.");
    }
    throw new IdentityError("INVALID_REFRESH_TOKEN", 401, "The refresh token is invalid or expired.");
  }
  if (current.revokedAt || current.expiresAt.getTime() <= Date.now()) {
    throw new IdentityError("INVALID_REFRESH_TOKEN", 401, "The refresh token is invalid or expired.");
  }

  const [user, organization, membership] = await Promise.all([
    User.findOne({ userId: current.userId, status: "active" }),
    Organization.findOne({ organizationId: current.organizationId, status: "active" }),
    Membership.findOne({ userId: current.userId, organizationId: current.organizationId, status: "active" })
  ]);
  if (!user || !organization || !membership) {
    current.revokedAt = new Date();
    await current.save();
    throw new IdentityError("SESSION_INACTIVE", 401, "The session is no longer active.");
  }

  const nextToken = createRefreshToken();
  const nextHash = hashRefreshToken(nextToken);
  const now = new Date();
  const dbSession = await mongoose.startSession();
  let rotated = false;
  try {
    await dbSession.withTransaction(async () => {
      rotated = false;
      const updated = await IdentitySession.findOneAndUpdate(
        { sessionId: current.sessionId, refreshTokenHash: oldHash, revokedAt: null, expiresAt: { $gt: now } },
        { $set: { refreshTokenHash: nextHash, lastUsedAt: now }, $addToSet: { previousRefreshTokenHashes: oldHash } },
        { new: true, session: dbSession }
      );
      if (!updated) return;
      await persistAudit({
        organizationId: current.organizationId, actorUserId: current.userId,
        action: "identity.refresh_rotated", targetType: "session", targetId: current.sessionId
      }, dbSession);
      rotated = true;
    });
  } finally {
    await dbSession.endSession();
  }
  if (!rotated) {
    const raced = await IdentitySession.findOne({ sessionId: current.sessionId }).select("+previousRefreshTokenHashes");
    if (raced && classifyRefreshToken(oldHash, null, raced.previousRefreshTokenHashes) === "replay") {
      if (!raced.revokedAt) {
        raced.revokedAt = now;
        await raced.save();
        await persistAudit({
          organizationId: raced.organizationId, actorUserId: raced.userId,
          action: "identity.refresh_reuse_detected", targetType: "session", targetId: raced.sessionId
        });
      }
      throw new IdentityError("REFRESH_TOKEN_REUSE", 401, "The session has been revoked. Please sign in again.");
    }
    throw new IdentityError("INVALID_REFRESH_TOKEN", 401, "The refresh token is invalid or expired.");
  }
  return {
    accessToken: issueAccessToken(current.userId, current.organizationId, current.sessionId, membership.role as Role),
    refreshToken: nextToken,
    expiresIn: ACCESS_TTL_SECONDS
  };
}

export async function revokeSession(input: { sessionId: string; userId: string; organizationId: string }): Promise<void> {
  const session = await IdentitySession.findOneAndUpdate(
    { sessionId: input.sessionId, userId: input.userId, organizationId: input.organizationId, revokedAt: null },
    { $set: { revokedAt: new Date() } },
    { new: true }
  );
  if (session) await persistAudit({
    organizationId: input.organizationId, actorUserId: input.userId,
    action: "identity.logout", targetType: "session", targetId: input.sessionId
  });
}
