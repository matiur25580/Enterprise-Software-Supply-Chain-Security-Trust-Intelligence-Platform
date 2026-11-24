import { Schema, model, models, type Model } from "mongoose";

const releasePassportSignerSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  keyId: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  algorithm: { type: String, enum: ["Ed25519"], required: true },
  publicKey: { type: String, required: true, maxlength: 4096 },
  status: { type: String, enum: ["active", "retired", "revoked"], required: true, default: "active" },
  activatedAt: { type: Date, required: true },
  activatedBy: { type: String, required: true, maxlength: 120 },
  rotatedFrom: { type: String, match: /^[a-f0-9]{64}$/ },
  retiredAt: { type: Date },
  revokedAt: { type: Date },
  revokedBy: { type: String, maxlength: 120 },
  revocationReason: { type: String, maxlength: 1000 }
}, { timestamps: true, strict: "throw", versionKey: false });

releasePassportSignerSchema.index({ tenantId:  1, keyId: 1 }, { unique: true });
releasePassportSignerSchema.index({ tenantId: 1, status: 1, activatedAt: -1 });
releasePassportSignerSchema.index({ tenantId: 1 }, { unique: true, partialFilterExpression: { status: "active" } });

const existing = models.ReleasePassportSigner as Model<any> | undefined;
export const ReleasePassportSigner: Model<any> = existing ?? model<any>("ReleasePassportSigner", releasePassportSignerSchema);
