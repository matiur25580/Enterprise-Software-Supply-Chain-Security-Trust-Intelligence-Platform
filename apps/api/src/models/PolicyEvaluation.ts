import { Schema, model, models, type Model } from "mongoose";

const policyCheckSchema = new Schema({
  id: { type: String, required: true, maxlength: 100 },
  status: { type: String, enum: ["pass", "warn", "block"], required: true },
  message: { type: String, required: true, maxlength: 500 },
  evidence: { type: Schema.Types.Mixed, default: {} }
}, { _id: false, strict: "throw" });

const policyEvaluationSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  sbomId: { type: Schema.Types.ObjectId, required: true, ref: "SbomRecord" },
  artifactDigest: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  policyVersion: { type: String, required: true, maxlength: 80 },
  outcome: { type: String, enum: ["pass", "warn", "block"], required: true },
  riskScore: { type: Number, required: true, min: 0, max: 100 },
  checks: { type: [policyCheckSchema], required: true, default: [] },
  evaluatedAt: { type: Date, required: true }
}, { timestamps: true, strict: "throw", versionKey: false });

policyEvaluationSchema.index({ tenantId: 1, evaluatedAt: -1 });
policyEvaluationSchema.index({ tenantId: 1, sbomId: 1, evaluatedAt: -1 });

const existing = models.PolicyEvaluation as Model<any> | undefined;
export const PolicyEvaluation: Model<any> = existing ?? model<any>("PolicyEvaluation", policyEvaluationSchema);
