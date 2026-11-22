import test, { before, after } from "node:test";
import { randomUUID } from "node:crypto";
import assert from "node:assert/strict";
import express from "express";
import mongoose from "mongoose";
import type { Server } from "node:http";
import { connectDatabase, disconnectDatabase } from "../config/database.js";
import { registerOrganization, login, rotateRefreshToken, IdentityError } from "./identity-service.js";
import { Membership, User, Organization, IdentitySession, AuditEvent } from "../models/identity.js";
import { authenticate } from "../middleware/authenticate.js";
import { requireOrganizationScope } from "../middleware/organization-scope.js";
import { requirePermission } from "../middleware/authorize.js";

before(async () => {
  await connectDatabase();
  await mongoose.connection.dropDatabase();
  await Promise.all([
    User.createIndexes(), Organization.createIndexes(), Membership.createIndexes(),
    IdentitySession.createIndexes(), AuditEvent.createIndexes()
  ]);
});

after(async () => {
  await disconnectDatabase();
});

test("persisted identity enforces tenant isolation, membership RBAC, and refresh replay revocation", async () => {
  const owner = await registerOrganization({
    email: "owner@chainproof.test",
    password: "owner-password-12345",
    displayName: "Workspace Owner",
    organizationName: "Owner Workspace",
    organizationSlug: "owner-workspace"
  });
  const secondOwner = await registerOrganization({
    email: "member@chainproof.test",
    password: "member-password-12345",
    displayName: "Second Workspace Owner",
    organizationName: "Second Workspace",
    organizationSlug: "second-workspace"
  });

  await Membership.create({
    membershipId: randomUUID(),
    organizationId: owner.organization.id,
    userId: secondOwner.user.id,
    role: "viewer",
    status: "active",
    createdByUserId: owner.user.id
  });

  const viewer = await login({
    email: "member@chainproof.test",
    password: "member-password-12345",
    organizationSlug: "owner-workspace"
  });

  const app = express();
  app.get("/organizations/:organizationId/manage",
    authenticate, requireOrganizationScope, requirePermission("members:manage"),
    (_request, response) => response.status(200).json({ ok: true })
  );
  const server: Server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const ownerAccess = await fetch(`${baseUrl}/organizations/${owner.organization.id}/manage`, {
      headers: { authorization: `Bearer ${owner.accessToken}` }
    });
    assert.equal(ownerAccess.status, 200);

    const crossTenant = await fetch(`${baseUrl}/organizations/${secondOwner.organization.id}/manage`, {
      headers: { authorization: `Bearer ${owner.accessToken}` }
    });
    assert.equal(crossTenant.status, 404);

    const viewerDenied = await fetch(`${baseUrl}/organizations/${owner.organization.id}/manage`, {
      headers: { authorization: `Bearer ${viewer.accessToken}` }
    });
    assert.equal(viewerDenied.status, 403);

    const rotated = await rotateRefreshToken(owner.refreshToken);
    assert.ok(rotated.refreshToken.length >= 60);
    await assert.rejects(
      () => rotateRefreshToken(owner.refreshToken),
      (error: unknown) => error instanceof IdentityError && error.code === "REFRESH_TOKEN_REUSE"
    );

    const revokedAccess = await fetch(`${baseUrl}/organizations/${owner.organization.id}/manage`, {
      headers: { authorization: `Bearer ${owner.accessToken}` }
    });
    assert.equal(revokedAccess.status, 401);

    await assert.rejects(
      () => rotateRefreshToken(rotated.refreshToken),
      (error: unknown) => error instanceof IdentityError && error.status === 401
    );
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
