import { policyEngineInstance } from "./policy-engine";

/**
 * Checks whether a user has a specific role for a given resource.
 *
 * This function performs runtime permission checking by delegating to the policy engine.
 * It verifies that the policy engine is initialized before making the check.
 *
 * @example
 * ```typescript
 * // Check if user can perform 'editor' role actions on a document
 * const canEdit = await hasRole('documents', 'editor', userId, documentId);
 *
 * // Check if user can perform 'admin' role actions on a project
 * const isAdmin = await hasRole('projects', 'admin', userId, projectId);
 * ```
 *
 * @param resourceType - The type of resource to check permissions for (e.g., 'documents', 'projects')
 * @param roleName - The name of the role to check (e.g., 'editor', 'viewer', 'admin')
 * @param userId - The ID of the user to check permissions for
 * @param resourceId - The ID of the specific resource instance
 * @returns Promise resolving to true if the user has the role, false otherwise
 * @throws Error if the policy engine is not initialized
 */
export const hasRole = async (
  resourceType: string,
  roleName: string,
  userId: string,
  resourceId: string
): Promise<boolean> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return (
    await policyEngineInstance.hasRole(
      resourceType,
      roleName,
      userId,
      resourceId
    )
  ).allowed;
};

/**
 * Checks whether a user has multiple roles on a resource.
 *
 * This function checks multiple roles in parallel and returns detailed results.
 * Returns `allowed: true` only if ALL roles are granted.
 *
 * @example
 * ```typescript
 * // Check if user has multiple roles
 * const result = await hasRoles(
 *   userId,
 *   { project: ['owner', 'editor'] },
 *   'project-123'
 * );
 * console.log(result.allowed); // true only if ALL roles granted
 * console.log(result.results); // { project: { owner: true, editor: false } }
 * ```
 *
 * @param userId - The ID of the user to check roles for
 * @param roles - An object mapping resource types to arrays of role names
 * @param resourceId - The ID of the specific resource instance
 * @returns Promise resolving to an object with allowed, message, and detailed results
 * @throws Error if the policy engine is not initialized
 */
export const hasRoles = async (
  userId: string,
  roles: Record<string, string[]>,
  resourceId: string
): Promise<{
  allowed: boolean;
  message: string;
  results?: Record<string, Record<string, boolean>>;
}> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return await policyEngineInstance.hasMultipleRoles(userId, roles, resourceId);
};

/**
 * Checks whether a user has a SINGLE permission on a resource.
 *
 * @example
 * ```typescript
 * // Check if user can read a document
 * const canRead = await hasPermission(userId, 'read', 'documents', documentId);
 *
 * // Check if user can delete a project
 * const canDelete = await hasPermission(userId, 'delete', 'projects', projectId);
 * ```
 *
 * @param userId - The ID of the user to check permissions for
 * @param action - The action to check (e.g., 'read', 'write', 'delete')
 * @param resourceType - The type of resource to check permissions for
 * @param resourceId - The ID of the specific resource instance
 * @returns Promise resolving to true if the permission is granted, false otherwise
 * @throws Error if the policy engine is not initialized
 */
export const hasPermission = async (
  userId: string,
  action: string,
  resourceType: string,
  resourceId: string
): Promise<boolean> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return (
    await policyEngineInstance.hasPermission(
      userId,
      action,
      resourceType,
      resourceId
    )
  ).allowed;
};

/**
 * Checks whether a user has MULTIPLE permissions on a resource.
 *
 * This function checks multiple permissions in parallel and returns detailed results.
 * Returns `allowed: true` only if ALL permissions are granted.
 *
 * @example
 * ```typescript
 * // Check multiple permissions
 * const result = await hasPermissions(
 *   userId,
 *   { project: ['create', 'update'] },
 *   'project-123'
 * );
 * console.log(result.allowed); // true only if ALL permissions granted
 * console.log(result.results); // { project: { create: true, update: false } }
 * ```
 *
 * @param userId - The ID of the user to check permissions for
 * @param permissions - An object mapping resource types to arrays of actions
 * @param resourceId - The ID of the specific resource instance
 * @returns Promise resolving to an object with allowed, message, and detailed results
 * @throws Error if the policy engine is not initialized
 */
export const hasPermissions = async (
  userId: string,
  permissions: Record<string, string[]>,
  resourceId: string
): Promise<{
  allowed: boolean;
  message: string;
  results?: Record<string, Record<string, boolean>>;
}> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return await policyEngineInstance.hasMultiplePermissions(
    userId,
    permissions,
    resourceId
  );
};
