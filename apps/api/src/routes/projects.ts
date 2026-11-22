import { randomUUID } from "node:crypto";
import { Router, type Router as ExpressRouter } from "express";
import { Project } from "../models/project.js";
import { AuditEvent } from "../models/identity.js";
import { createProjectSchema, listProjectsQuerySchema, updateProjectSchema } from "../projects/schemas.js";
import { projectTenantFilter } from "../projects/scope.js";
import { authenticate } from "../middleware/authenticate.js";
import { requireOrganizationScope } from "../middleware/organization-scope.js";
import { requirePermission } from "../middleware/authorize.js";

export const projectsRouter: ExpressRouter = Router();
const route = "/organizations/:organizationId/projects";

function routeParameter(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

projectsRouter.get(route,
  authenticate, requireOrganizationScope, requirePermission("projects:read"),
  async (request, response, next) => {
    const parsed = listProjectsQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      response.status(400).json({ error: { code: "INVALID_REQUEST", message: "The query is invalid." } });
      return;
    }
    try {
      const filter = projectTenantFilter(request.auth!.orgId);
      const query = { ...filter, ...(parsed.data.status ? { status: parsed.data.status } : {}) };
      const projects = await Project.find(query).sort({ updatedAt: -1, projectId: 1 })
        .limit(parsed.data.limit).lean();
      response.status(200).json({ data: projects });
    } catch (error) { next(error); }
  }
);

projectsRouter.post(route,
  authenticate, requireOrganizationScope, requirePermission("projects:write"),
  async (request, response, next) => {
    const parsed = createProjectSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ error: { code: "INVALID_REQUEST", message: "The request is invalid.", fields: parsed.error.flatten().fieldErrors } });
      return;
    }
    try {
      const organizationId = request.auth!.orgId;
      const projectId = randomUUID();
      const project = await Project.create({
        projectId, organizationId, ...parsed.data,
        createdByUserId: request.auth!.sub, updatedByUserId: request.auth!.sub
      });
      await AuditEvent.create({
        eventId: randomUUID(), organizationId, actorUserId: request.auth!.sub,
        action: "project.created", targetType: "project", targetId: projectId,
        metadata: { slug: project.slug }
      });
      response.status(201).json({ data: project.toJSON() });
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === 11000) {
        response.status(409).json({ error: { code: "PROJECT_SLUG_EXISTS", message: "A project with this identifier already exists in the organization." } });
        return;
      }
      next(error);
    }
  }
);

projectsRouter.get(`${route}/:projectId`,
  authenticate, requireOrganizationScope, requirePermission("projects:read"),
  async (request, response, next) => {
    const projectId = routeParameter(request.params.projectId);
    if (!projectId) {
      response.status(404).json({ error: { code: "RESOURCE_NOT_FOUND", message: "The requested project was not found." } });
      return;
    }
    try {
      const project = await Project.findOne(projectTenantFilter(request.auth!.orgId, projectId)).lean();
      if (!project) {
        response.status(404).json({ error: { code: "RESOURCE_NOT_FOUND", message: "The requested project was not found." } });
        return;
      }
      response.status(200).json({ data: project });
    } catch (error) { next(error); }
  }
);

projectsRouter.patch(`${route}/:projectId`,
  authenticate, requireOrganizationScope, requirePermission("projects:write"),
  async (request, response, next) => {
    const projectId = routeParameter(request.params.projectId);
    if (!projectId) {
      response.status(404).json({ error: { code: "RESOURCE_NOT_FOUND", message: "The requested project was not found." } });
      return;
    }
    const parsed = updateProjectSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ error: { code: "INVALID_REQUEST", message: "The request is invalid.", fields: parsed.error.flatten().fieldErrors } });
      return;
    }
    try {
      const organizationId = request.auth!.orgId;
      const project = await Project.findOneAndUpdate(
        projectTenantFilter(organizationId, projectId),
        { $set: { ...parsed.data, updatedByUserId: request.auth!.sub } },
        { new: true, runValidators: true }
      );
      if (!project) {
        response.status(404).json({ error: { code: "RESOURCE_NOT_FOUND", message: "The requested project was not found." } });
        return;
      }
      await AuditEvent.create({
        eventId: randomUUID(), organizationId, actorUserId: request.auth!.sub,
        action: "project.updated", targetType: "project", targetId: project.projectId,
        metadata: { fields: Object.keys(parsed.data) }
      });
      response.status(200).json({ data: project.toJSON() });
    } catch (error) { next(error); }
  }
);
