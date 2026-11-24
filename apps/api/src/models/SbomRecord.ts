import { Schema, model, models, type Model } from "mongoose";

const sbomRecordSchema = new Schema({
  // Tenant ownership must be derived from authenticated server context.
  tenantId: { type: String, required: true, trim: true, maxlength: 120 },
  ingestionJobId: { type: Schema.Types.ObjectId, ref: "SbomIngestionJob" },
  format: { type: String, enum: ["cyclonedx", "spdx"], required: true },
  formatVersion: { type: String, required: true, maxlength: 40 },
  documentName: { type: String, required: true, trim: true, maxlength: 200 },
  documentVersion: { type: String, maxlength: 100 },
  componentCount: { type: Number, required: true, min: 0, max: 1000000 },
  source: { type: String, maxlength: 500 },
  documentDigest: { type: String, match: /^[a-f0-9]{64}$/i },
  normalizedComponents: { type: [{ name: { type: String, required: true, maxlength: 500 }, version: { type: String, maxlength: 200 }, purl: { type: String, maxlength: 1024 }, supplier: { type: String, maxlength: 200 }, componentType: { type: String, maxlength: 80 }, bomRef: { type: String, maxlength: 500 }, _id: false }], default: [] },
  normalizedDependencies: { type: [{ from: { type: String, required: true, maxlength: 500 }, to: { type: String, required: true, maxlength: 500 }, relationshipType: { type: String, required: true, maxlength: 100 }, _id: false }], default: [] },
  ingestionStatus: {
    type: String,
    enum: ["received", "validated", "rejected"],
    default: "received",
    required: true
  }
}, {
  timestamps: true,
  strict: "throw",
  versionKey: false
});

// Tenant-scoped listing is the expected access pattern; do not query this
// collection by document ID alone in authenticated application services.
sbomRecordSchema.index({ tenantId: 1, createdAt: -1 });
sbomRecordSchema.index({ tenantId: 1, ingestionJobId: 1 }, { unique: true, partialFilterExpression: { ingestionJobId: { $type: "objectId" } } });
sbomRecordSchema.index({ tenantId: 1, documentDigest: 1 }, { unique: true, partialFilterExpression: { documentDigest: { $type: "string" } } });

const existingSbomRecordModel = models.SbomRecord as Model<any> | undefined;
export const SbomRecord: Model<any> = existingSbomRecordModel ?? model<any>("SbomRecord", sbomRecordSchema);