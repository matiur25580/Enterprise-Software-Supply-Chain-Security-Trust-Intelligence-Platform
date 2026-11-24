import { Schema, model, models, type Model } from "mongoose";

const jobPayloadSchema = new Schema({
  format: { type: String, enum: ["cyclonedx", "spdx"], required: true },
  formatVersion: { type: String, required: true, maxlength: 40 },
  documentName: { type: String, required: true, maxlength: 200 },
  documentVersion: { type: String, maxlength: 100 },
  componentCount: { type: Number, required: true, min: 0, max: 10000 },
  documentDigest: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  normalizedComponents: { type: [Schema.Types.Mixed], required: true },
  normalizedDependencies: { type: [Schema.Types.Mixed], required: true }
}, { _id: false, strict: "throw" });

const sbomIngestionJobSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  status: { type: String, enum: ["queued", "processing", "completed", "failed"], required: true, default: "queued" },
  payload: { type: jobPayloadSchema, required: true },
  source: { type: String, maxlength: 500 },
  attempts: { type: Number, required: true, default: 0, min: 0, max: 3 },
  maxAttempts: { type: Number, required: true, default: 3, min: 1, max: 3 },
  availableAt: { type: Date, required: true, default: Date.now },
  lockedAt: { type: Date },
  workerId: { type: String, maxlength: 120 },
  lastError: { type: String, maxlength: 500 },
  sbomId: { type: Schema.Types.ObjectId, ref: "SbomRecord" },
  completedAt: { type: Date },
  expiresAt: { type: Date }
}, { timestamps: true, strict: "throw", versionKey: false });

sbomIngestionJobSchema.index({ status: 1, availableAt: 1, createdAt: 1 });
sbomIngestionJobSchema.index({ tenantId: 1, createdAt: -1 });
sbomIngestionJobSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, partialFilterExpression: { expiresAt: { $type: "date" } } });

const existing = models.SbomIngestionJob as Model<any> | undefined;
export const SbomIngestionJob: Model<any> = existing ?? model<any>("SbomIngestionJob", sbomIngestionJobSchema);
