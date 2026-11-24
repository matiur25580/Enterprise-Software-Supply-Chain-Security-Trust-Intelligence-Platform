import { Schema, model, models, type Model } from "mongoose";

const releaseTrustPassportSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  passportId: { type: String, required: true, match: /^[0-9a-f-]{36}$/i },
  evaluationId: { type: Schema.Types.ObjectId, required: true, ref: "PolicyEvaluation" },
  artifactDigest: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  algorithm: { type: String, enum: ["Ed25519"], required: true },
  keyId: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  publicKey: { type: String, required: true, maxlength: 4096 },
  payload: { type: Schema.Types.Mixed, required: true },
  signature: { type: String, required: true, maxlength: 512 },
  signedAt: { type: Date, required: true }
}, { timestamps: true, strict: "throw", versionKey: false });

releaseTrustPassportSchema.index({ tenantId: 1, passportId: 1 }, { unique: true });
releaseTrustPassportSchema.index({ tenantId: 1, artifactDigest: 1, signedAt: -1 });

const existing = models.ReleaseTrustPassport as Model<any> | undefined;
export const ReleaseTrustPassport: Model<any> = existing ?? model<any>("ReleaseTrustPassport", releaseTrustPassportSchema);
