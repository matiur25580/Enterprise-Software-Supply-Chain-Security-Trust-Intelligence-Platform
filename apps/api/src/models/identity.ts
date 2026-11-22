import { Schema, model, models } from "mongoose";
import { roles } from "../auth/roles.js";

const userSchema = new Schema({
  userId: { type: String, required: true, unique: true, immutable: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  displayName: { type: String, required: true, trim: true, maxlength: 100 },
  passwordHash: { type: String, required: true, select: false },
  status: { type: String, enum: ["active", "disabled"], default: "active", required: true }
}, { timestamps: true, versionKey: false });
userSchema.index({ email: 1 }, { unique: true, name: "users_email_unique" });

const organizationSchema = new Schema({
  organizationId: { type: String, required: true, unique: true, immutable: true },
  name: { type: String, required: true, trim: true, maxlength: 120 },
  slug: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 63 },
  status: { type: String, enum: ["active", "suspended"], default: "active", required: true }
}, { timestamps: true, versionKey: false });
organizationSchema.index({ slug: 1 }, { unique: true, name: "organizations_slug_unique" });

const membershipSchema = new Schema({
  membershipId: { type: String, required: true, unique: true, immutable: true },
  organizationId: { type: String, required: true, immutable: true },
  userId: { type: String, required: true, immutable: true },
  role: { type: String, enum: roles, required: true },
  status: { type: String, enum: ["active", "suspended", "removed"], default: "active", required: true },
  createdByUserId: { type: String, required: true, immutable: true }
}, { timestamps: true, versionKey: false });
membershipSchema.index({ organizationId: 1, userId: 1 }, { unique: true, name: "memberships_org_user_unique" });
membershipSchema.index({ userId: 1, status: 1 }, { name: "memberships_user_status" });

const sessionSchema = new Schema({
  sessionId: { type: String, required: true, unique: true, immutable: true },
  userId: { type: String, required: true, immutable: true },
  organizationId: { type: String, required: true, immutable: true },
  refreshTokenHash: { type: String, required: true, select: false },
  previousRefreshTokenHashes: { type: [String], default: [], select: false },
  expiresAt: { type: Date, required: true },
  lastUsedAt: { type: Date, default: null },
  revokedAt: { type: Date, default: null }
}, { timestamps: true, versionKey: false });
sessionSchema.index({ sessionId: 1 }, { unique: true, name: "sessions_session_id_unique" });
sessionSchema.index({ refreshTokenHash: 1 }, { unique: true, name: "sessions_refresh_hash_unique" });
sessionSchema.index({ userId: 1, organizationId: 1, revokedAt: 1 }, { name: "sessions_user_org_active" });
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, name: "sessions_expiry_ttl" });

const auditEventSchema = new Schema({
  eventId: { type: String, required: true, unique: true, immutable: true },
  organizationId: { type: String, required: true, immutable: true },
  actorUserId: { type: String, required: true, immutable: true },
  action: { type: String, required: true, maxlength: 120 },
  targetType: { type: String, required: true, maxlength: 80 },
  targetId: { type: String, default: null, maxlength: 128 },
  metadata: { type: Schema.Types.Mixed, default: {} }
}, { timestamps: { createdAt: true, updatedAt: false }, versionKey: false });
auditEventSchema.index({ organizationId: 1, createdAt: -1 }, { name: "audit_org_timeline" });
auditEventSchema.index({ organizationId: 1, actorUserId: 1, createdAt: -1 }, { name: "audit_org_actor_timeline" });

export const User = models.User ?? model("User", userSchema);
export const Organization = models.Organization ?? model("Organization", organizationSchema);
export const Membership = models.Membership ?? model("Membership", membershipSchema);
export const IdentitySession = models.IdentitySession ?? model("IdentitySession", sessionSchema);
export const AuditEvent = models.AuditEvent ?? model("AuditEvent", auditEventSchema);
