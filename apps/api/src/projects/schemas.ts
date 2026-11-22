import { z } from "zod";

const slug = z.string().trim().toLowerCase().min(2).max(63)
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
const repositoryUrl = z.string().url().max(2048).refine((value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch { return false; }
}, "Repository URL must be HTTPS and must not contain credentials.");

export const createProjectSchema = z.object({
  name: z.string().trim().min(2).max(120),
  slug,
  description: z.string().trim().max(1000).default(""),
  repositoryUrl,
  defaultBranch: z.string().trim().min(1).max(255).default("main")
}).strict();

export const updateProjectSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  description: z.string().trim().max(1000).optional(),
  repositoryUrl: repositoryUrl.optional(),
  defaultBranch: z.string().trim().min(1).max(255).optional(),
  status: z.enum(["active", "archived"]).optional()
}).strict().refine((value) => Object.keys(value).length > 0, "At least one field is required.");

export const listProjectsQuerySchema = z.object({
  status: z.enum(["active", "archived"]).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  cursor: z.string().uuid().optional()
}).strict();
