import test from "node:test";
import assert from "node:assert/strict";
import { AuditEvent, IdentitySession, Membership, Organization, User } from "../models/identity.js";

function hasIndex(schema: { indexes(): unknown[] }, key: Record<string, number>, unique = false): boolean {
  return schema.indexes().some((entry) => {
    if (!Array.isArray(entry)) return false;
    const [keys, options] = entry as [Record<string, unknown>, { unique?: boolean }];
    return JSON.stringify(keys) === JSON.stringify(key) && (!unique || options.unique === true);
  });
}

test("identity models declare normalized unique account and organization identifiers", () => {
  assert.equal(hasIndex(User.schema, { email: 1 }, true), true);
  assert.equal(hasIndex(Organization.schema, { slug: 1 }, true), true);
});

test("membership and refresh-session indexes enforce tenant and session boundaries", () => {
  assert.equal(hasIndex(Membership.schema, { organizationId: 1, userId: 1 }, true), true);
  assert.equal(hasIndex(IdentitySession.schema, { refreshTokenHash: 1 }, true), true);
  assert.equal(hasIndex(IdentitySession.schema, { expiresAt: 1 }), true);
});

test("audit indexes partition timelines by tenant", () => {
  assert.equal(hasIndex(AuditEvent.schema, { organizationId: 1, createdAt: -1 }), true);
});
