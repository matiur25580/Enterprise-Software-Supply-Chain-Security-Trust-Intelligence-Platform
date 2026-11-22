export function projectTenantFilter(organizationId: string, projectId?: string) {
  return projectId
    ? { organizationId, projectId }
    : { organizationId };
}
