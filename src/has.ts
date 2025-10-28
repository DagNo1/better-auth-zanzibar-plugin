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
 * Checks multiple named permission checks, each targeting potentially different resources.
 *
 * This function allows you to perform multiple permission checks with custom names,
 * where each check can target different resource types, actions, and resource IDs.
 *
 * @example
 * ```typescript
 * // Check various permissions with custom names
 * const result = await hasNamedPermissions(userId, {
 *   project: {
 *     resourceType: 'project',
 *     actions: ['create', 'update', 'delete'],
 *     resourceId: 'project-123'
 *   },
 *   folderCreate: {
 *     resourceType: 'folder',
 *     action: 'create',
 *     resourceId: 'folder-456'
 *   },
 *   folderEdit: {
 *     resourceType: 'folder',
 *     action: 'edit',
 *     resourceId: 'folder-456'
 *   }
 * });
 *
 * console.log(result.project.allowed); // false
 * console.log(result.project.results); // { create: true, update: true, delete: false }
 * console.log(result.folderCreate.allowed); // true
 * console.log(result.folderEdit.allowed); // true
 * ```
 *
 * @param userId - The ID of the user to check permissions for
 * @param checks - Object with custom keys mapping to permission check definitions
 * @returns Promise resolving to an object with results keyed by the custom names
 * @throws Error if the policy engine is not initialized
 */
export const hasNamedPermissions = async (
  userId: string,
  checks: Record<
    string,
    {
      resourceType: string;
      action?: string;
      actions?: string[];
      resourceId: string;
    }
  >
): Promise<
  Record<
    string,
    {
      allowed: boolean;
      message: string;
      results?: Record<string, boolean>;
    }
  >
> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return await policyEngineInstance.hasNamedPermissions(userId, checks);
};
