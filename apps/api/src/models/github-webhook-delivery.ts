import mongoose, { Schema, model, type Model } from "mongoose";

const githubWebhookDeliverySchema = new Schema({
  deliveryId: { type: String, required: true, immutable: true },
  eventName: { type: String, required: true, maxlength: 100 },
  action: { type: String, default: null, maxlength: 80 },
  installationId: { type: Number, default: null },
  repositoryId: { type: Number, default: null },
  senderId: { type: Number, default: null },
  payloadSha256: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  processingStatus: { type: String, enum: ["received", "queued", "processed", "failed"], default: "queued", required: true },
  receivedAt: { type: Date, required: true, default: Date.now },
  processedAt: { type: Date, default: null }
}, { timestamps: true, versionKey: false });

githubWebhookDeliverySchema.index({ deliveryId: 1 }, { unique: true, name: "github_webhook_delivery_unique" });
githubWebhookDeliverySchema.index({ processingStatus: 1, receivedAt: 1 }, { name: "github_webhook_work_queue" });
githubWebhookDeliverySchema.index({ installationId: 1, receivedAt: -1 }, { name: "github_webhook_installation_timeline" });

export const GitHubWebhookDelivery: Model<any> =
  (mongoose.models.GitHubWebhookDelivery as Model<any> | undefined) ??
  model("GitHubWebhookDelivery", githubWebhookDeliverySchema);
