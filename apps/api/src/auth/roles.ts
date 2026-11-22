export const roles = ["platform_admin", "org_owner", "org_admin", "security_analyst", "developer", "auditor", "viewer"] as const;
export type Role = (typeof roles)[number];

export const permissions = [
  "organization:read", "organization:update", "members:read", "members:invite", "members:manage",
  "projects:read", "projects:write", "integrations:manage", "findings:read", "findings:triage", "policies:read", "policies:write",
  "audit:read", "settings:manage"
] as const;
export type Permission = (typeof permissions)[number];

const rolePermissions: Record<Role, readonly Permission[]> = {
  platform_admin: permissions,
  org_owner: permissions,
  org_admin: permissions.filter((p) => p !== "settings:manage"),
  security_analyst: ["organization:read", "members:read", "projects:read", "findings:read", "findings:triage", "policies:read", "audit:read"],
  developer: ["organization:read", "projects:read", "findings:read", "findings:triage", "policies:read"],
  auditor: ["organization:read", "members:read", "projects:read", "findings:read", "policies:read", "audit:read"],
  viewer: ["organization:read", "projects:read", "findings:read", "policies:read"]
};

export function hasPermission(userRoles: readonly Role[], permission: Permission): boolean {
  return userRoles.some((role) => rolePermissions[role]?.includes(permission) ?? false);
}
