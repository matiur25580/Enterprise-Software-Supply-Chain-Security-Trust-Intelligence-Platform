import { Schema, model, models, type Model } from "mongoose";

const vexExceptionSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  sbomId: { type: Schema.Types.ObjectId, required: true, ref: "SbomRecord" },
  scanId: { type: Schema.Types.ObjectId, required: true, ref: "VulnerabilityScan" },
  advisoryId: { type: String, required: true, trim: true, maxlength: 120 },
  purl: { type: String, required: true, trim: true, maxlength: 1024 },
  rationale: { type: String, required: true, trim: true, minlength: 20, maxlength: 2000 },
  compensatingControls: { type: String, required: true, trim: true, minlength: 10, maxlength: 2000 },
  status: { type: String, enum: ["accepted", "revoked"], required: true, default: "accepted" },
  acceptedBy: { type: String, required: true, maxlength: 120 },
  acceptedAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
  revokedBy: { type: String, maxlength: 120 },
  revokedAt: { type: Date }
}, { timestamps: true, strict: "throw", versionKey: false });

vexExceptionSchema.index({ tenantId: 1, sbomId: 1, advisoryId: 1, purl: 1, expiresAt: 1 });
vexExceptionSchema.index({ tenantId: 1, status: 1, expiresAt: 1 });

const existing = models.VexRiskAcceptance as Model<any> | undefined;
export const VexRiskAcceptance: Model<any> = existing ?? model<any>("VexRiskAcceptance", vexExceptionSchema);
