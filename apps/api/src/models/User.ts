import { Schema, model, models } from "mongoose";

export const CHAINPROOF_ROLES = ["platform-admin", "security-analyst", "developer", "auditor"] as const;

const userSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  email: { type: String, required: true, lowercase: true, trim: true, maxlength: 254 },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, enum: CHAINPROOF_ROLES, required: true },
  active: { type: Boolean, default: true, required: true }
}, { timestamps: true, strict: "throw", versionKey: false });

// Email is unique within a tenant, not globally across customer organizations.
userSchema.index({ tenantId: 1, email: 1 }, { unique: true });

export const User = models.User ?? model("User", userSchema);