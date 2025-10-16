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
 * const canEdit = await checkRole('documents', 'editor', userId, documentId);
 *
 * // Check if user can perform 'admin' role actions on a project
 * const isAdmin = await checkRole('projects', 'admin', userId, projectId);
 * ```
 *
 * @param resourceType - The type of resource to check permissions for (e.g., 'documents', 'projects')
 * @param roleName - The name of the role to check (e.g., 'editor', 'viewer', 'admin')
 * @param userId - The ID of the user to check permissions for
 * @param resourceId - The ID of the specific resource instance
 * @returns Promise resolving to true if the user has the role, false otherwise
 * @throws Error if the policy engine is not initialized
 */
export const checkRole = async (
  resourceType: string,
  roleName: string,
  userId: string,
  resourceId: string
): Promise<boolean> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return (
    await policyEngineInstance.checkRole(
      resourceType,
      roleName,
      userId,
      resourceId
    )
  ).allowed;
};

/**
 * Checks whether a user can perform a specific action on a resource.
 *
 * This function provides a lower-level permission check that directly validates
 * if a user has permission to perform a particular action on a resource, bypassing
 * the role-based abstraction.
 *
 * @example
 * ```typescript
 * // Check if user can read a document
 * const canRead = await check(userId, 'read', 'documents', documentId);
 *
 * // Check if user can delete a project
 * const canDelete = await check(userId, 'delete', 'projects', projectId);
 *
 * // Check if user can write to a document
 * const canWrite = await check(userId, 'write', 'documents', documentId);
 * ```
 *
 * @param userId - The ID of the user to check permissions for
 * @param action - The specific action to check (e.g., 'read', 'write', 'delete', 'view', 'edit')
 * @param resourceType - The type of resource to check permissions for
 * @param resourceId - The ID of the specific resource instance
 * @returns Promise resolving to true if the action is allowed, false otherwise
 * @throws Error if the policy engine is not initialized
 */
export const check = async (
  userId: string,
  action: string,
  resourceType: string,
  resourceId: string
): Promise<boolean> => {
  if (!policyEngineInstance) throw new Error("Policy engine not initialized");
  return (
    await policyEngineInstance.check(userId, action, resourceType, resourceId)
  ).allowed;
};
