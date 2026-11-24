import { Schema, model, models, type Model } from "mongoose";

const sbomIngestionJobSchema = new Schema({
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  status: { type: String, enum: ["queued", "processing", "completed", "failed"], required: true, default: "queued" },
  // Raw JSON is retained only while queued/processing and removed at terminal state.
  rawDocument: { type: Schema.Types.Mixed, required: true },
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
