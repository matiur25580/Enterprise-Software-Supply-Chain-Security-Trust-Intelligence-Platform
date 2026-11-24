import { Schema, model, models, type Model } from "mongoose";

const artifactVerificationSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  artifactDigest: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  digestAlgorithm: { type: String, enum: ["sha256"], required: true },
  verificationType: { type: String, enum: ["sigstore-slsa-provenance"], required: true },
  status: { type: String, enum: ["verified", "rejected"], required: true },
  certificateIssuer: { type: String, maxlength: 500 },
  certificateIdentity: { type: String, maxlength: 1000 },
  predicateType: { type: String, maxlength: 300 },
  buildType: { type: String, maxlength: 1000 },
  builderId: { type: String, maxlength: 1000 },
  sourceRepository: { type: String, maxlength: 1000 },
  sourceCommit: { type: String, maxlength: 200 },
  invocationId: { type: String, maxlength: 1000 },
  failureCode: { type: String, enum: ["policy_not_configured", "invalid_bundle", "signature_invalid", "provenance_invalid", "artifact_digest_mismatch", "builder_not_allowed"] }
}, { timestamps: true, strict: "throw", versionKey: false });

artifactVerificationSchema.index({ tenantId: 1, createdAt: -1 });
artifactVerificationSchema.index({ tenantId: 1, artifactDigest: 1, createdAt: -1 });

const existing = models.ArtifactVerification as Model<any> | undefined;
export const ArtifactVerification: Model<any> = existing ?? model<any>("ArtifactVerification", artifactVerificationSchema);
