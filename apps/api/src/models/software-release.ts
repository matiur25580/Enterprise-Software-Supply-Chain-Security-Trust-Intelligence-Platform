import mongoose, { Schema, model, type Model } from "mongoose";

const provenanceSchema = new Schema({
  sourceRepository: { type: String, required: true, maxlength: 300, immutable: true },
  sourceCommitSha: { type: String, required: true, match: /^[a-f0-9]{40}$/i, immutable: true },
  builderIdentity: { type: String, required: true, maxlength: 300, immutable: true },
  buildRunUrl: { type: String, required: true, maxlength: 2048, immutable: true },
  attestationDigest: { type: String, default: null, match: /^[a-f0-9]{64}$/i, immutable: true }
}, { _id: false, versionKey: false });

const trustFactorSchema = new Schema({
  key: { type: String, required: true },
  points: { type: Number, required: true },
  explanation: { type: String, required: true, maxlength: 500 }
}, { _id: false, versionKey: false });

const softwareReleaseSchema = new Schema({
  releaseId: { type: String, required: true, unique: true, immutable: true },
  organizationId: { type: String, required: true, immutable: true },
  projectId: { type: String, required: true, immutable: true },
  sbomId: { type: String, required: true, immutable: true },
  version: { type: String, required: true, maxlength: 128, immutable: true },
  artifactSha256: { type: String, required: true, match: /^[a-f0-9]{64}$/i, immutable: true },
  provenance: { type: provenanceSchema, required: true, immutable: true },
  provenanceVerification: { type: String, enum: ["not_verified"], default: "not_verified", required: true, immutable: true },
  vulnerabilitySummary: {
    critical: { type: Number, required: true, min: 0 },
    high: { type: Number, required: true, min: 0 },
    moderate: { type: Number, required: true, min: 0 },
    low: { type: Number, required: true, min: 0 },
    unknown: { type: Number, required: true, min: 0 }
  },
  trustScore: { type: Number, required: true, min: 0, max: 100 },
  trustFactors: { type: [trustFactorSchema], default: [] },
  policyStatus: { type: String, enum: ["eligible", "blocked"], required: true },
  policyReasons: { type: [{ type: String, maxlength: 500 }], default: [] },
  createdByUserId: { type: String, required: true, immutable: true }
}, { timestamps: true, versionKey: false });

softwareReleaseSchema.index({ organizationId: 1, projectId: 1, createdAt: -1 }, { name: "software_releases_project_timeline" });
softwareReleaseSchema.index({ organizationId: 1, projectId: 1, version: 1, artifactSha256: 1 }, { unique: true, name: "software_release_artifact_unique" });

export const SoftwareRelease: Model<any> =
  (mongoose.models.SoftwareRelease as Model<any> | undefined) ??
  model("SoftwareRelease", softwareReleaseSchema);
