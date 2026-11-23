import { Router, type Router as ExpressRouter } from "express";
import { authenticate } from "../middleware/authenticate.js";
import { requireOrganizationScope } from "../middleware/organization-scope.js";
import { requirePermission } from "../middleware/authorize.js";

export const accessRouter: ExpressRouter = Router();
accessRouter.get("/organizations/:organizationId/context",
  authenticate, requireOrganizationScope, requirePermission("organization:read"),
  (request, response) => {
    response.status(200).json({
      data: {
        organizationId: request.organizationId,
        subject: request.auth?.sub,
        roles: request.auth?.roles
      }
    });
  }
);
