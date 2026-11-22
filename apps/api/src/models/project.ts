import { Schema, model, models, type Model } from "mongoose";

const projectSchema = new Schema({
  projectId: { type: String, required: true, unique: true, immutable: true },
  organizationId: { type: String, required: true, immutable: true },
  name: { type: String, required: true, trim: true, maxlength: 120 },
  slug: { type: String, required: true, lowercase: true, trim: true, maxlength: 63 },
  description: { type: String, default: "", trim: true, maxlength: 1000 },
  repositoryUrl: { type: String, required: true, maxlength: 2048 },
  defaultBranch: { type: String, required: true, default: "main", trim: true, maxlength: 255 },
  status: { type: String, enum: ["active", "archived"], default: "active", required: true },
  createdByUserId: { type: String, required: true, immutable: true },
  updatedByUserId: { type: String, required: true }
}, { timestamps: true, versionKey: false });

projectSchema.index({ organizationId: 1, slug: 1 }, { unique: true, name: "projects_org_slug_unique" });
projectSchema.index({ organizationId: 1, status: 1, updatedAt: -1 }, { name: "projects_org_status_updated" });

export const Project: Model<any> = (models.Project as Model<any> | undefined) ?? model("Project", projectSchema);
