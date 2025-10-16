import type {
  ConditionsShape,
  RelationshipFunction,
  ResourcesShape,
} from "./types";
import type { Policies, ResourceRole } from "./types";
import { checkRole as runtimeCheckRole } from "./check";

/**
 * Creates an access control builder for defining and checking permissions in a Zanzibar-based authorization system.
 *
 * This function implements the builder pattern to construct access control policies step by step:
 * 1. Define available resources and their actions
 * 2. Define roles that group actions for each resource
 * 3. Add conditions (business logic) for role evaluation
 * 4. Check permissions at runtime
 *
 * @example
 * ```typescript
 * const accessControl = createAccessControl({
 *   documents: ['read', 'write', 'delete'] as const,
 *   projects: ['view', 'edit', 'manage'] as const,
 * })
 *   .resourceRoles({
 *     documents: [
 *       { name: 'viewer', actions: ['read'] },
 *       { name: 'editor', actions: ['read', 'write'] },
 *       { name: 'admin', actions: ['read', 'write', 'delete'] },
 *     ],
 *     projects: [
 *       { name: 'member', actions: ['view'] },
 *       { name: 'maintainer', actions: ['view', 'edit'] },
 *       { name: 'owner', actions: ['view', 'edit', 'manage'] },
 *     ],
 *   })
 *   .roleConditions({
 *     documents: {
 *       viewer: async (userId, documentId) => {
 *         // Check if user has read access to document
 *         return await hasDocumentAccess(userId, documentId, 'read');
 *       },
 *       editor: async (userId, documentId) => {
 *         // Check if user has write access to document
 *         return await hasDocumentAccess(userId, documentId, 'write');
 *       },
 *     },
 *   });
 *
 * // Check permissions at runtime
 * const canEdit = await accessControl.checkRole('documents', 'editor', userId, documentId);
 * ```
 *
 * @template TResources - Shape defining available resources and their actions
 * @param resources - Object mapping resource types to their available actions
 * @returns Object with `resourceRoles` method to define roles
 */
export function createAccessControl<TResources extends ResourcesShape>(
  resources: TResources
) {
  /**
   * Defines roles for each resource type, where each role groups together specific actions.
   *
   * This function validates that:
   * - All referenced resources exist in the original resources definition
   * - All actions in roles are valid actions for their respective resources
   *
   * @example
   * ```typescript
   * .resourceRoles({
   *   documents: [
   *     { name: 'viewer', actions: ['read'] },
   *     { name: 'editor', actions: ['read', 'write'] },
   *   ]
   * })
   * ```
   *
   * @template TRoles - Shape defining roles for each resource type
   * @param roles - Object mapping resource types to arrays of role definitions
   * @returns Object with `roleConditions` method to add business logic
   */
  function resourceRoles<
    TRoles extends {
      readonly [K in keyof TResources]?: ReadonlyArray<{
        name: string;
        actions: ReadonlyArray<TResources[K][number]>;
      }>;
    },
  >(roles: TRoles) {
    // Runtime validation: resources and actions
    for (const [resource, roleList] of Object.entries(roles)) {
      if (!(resource in resources)) {
        throw new Error(`Unknown resource '${resource}' in roles`);
      }
      const allowedActions = new Set(resources[resource as keyof TResources]);
      for (const role of roleList ?? []) {
        for (const action of role.actions) {
          if (!allowedActions.has(action as string)) {
            throw new Error(
              `Unknown action '${action}' for resource '${resource}'`
            );
          }
        }
      }
    }

    type RoleNameMap = {
      [K in keyof TResources]: TRoles[K] extends ReadonlyArray<infer RR>
        ? RR extends { name: infer N }
          ? Extract<N, string>
          : never
        : never;
    };

    /**
     * Adds business logic conditions for role evaluation.
     *
     * Conditions are async functions that implement the actual permission logic.
     * They receive the user ID and resource ID and return a boolean indicating
     * whether the user should be granted the role for that specific resource.
     *
     * This function validates that:
     * - All referenced resources exist
     * - All referenced roles have been defined in the previous step
     *
     * @example
     * ```typescript
     * .roleConditions({
     *   documents: {
     *     viewer: async (userId, documentId) => {
     *       // Custom logic: check if user is owner or has been shared the document
     *       return await isDocumentOwner(userId, documentId) ||
     *              await isDocumentSharedWith(userId, documentId);
     *     }
     *   }
     * })
     * ```
     *
     * @param conditions - Object mapping resource types to role condition functions
     * @returns Complete policies object for use with ZanzibarPlugin
     */
    function roleConditions(conditions: ConditionsShape<TResources, TRoles>) {
      // Runtime validation: referenced resources/roles exist
      for (const [resource, roleMap] of Object.entries(conditions)) {
        if (!(resource in resources)) {
          throw new Error(`Unknown resource '${resource}' in conditions`);
        }
        const definedRoles = new Set(
          (roles as any)[resource]?.map((r: any) => r.name) ?? []
        );
        for (const roleName of Object.keys(roleMap ?? {})) {
          if (!definedRoles.has(roleName)) {
            throw new Error(
              `Unknown role '${roleName}' for resource '${resource}' in conditions`
            );
          }
        }
      }

      // Build Policies object for ZanzibarPlugin
      const policy = Object.keys(resources).reduce((acc, resourceType) => {
        const actions = [...(resources as any)[resourceType]] as string[];
        const roleDefs = ((roles as any)[resourceType] ?? []) as ReadonlyArray<{
          name: string;
          actions: readonly string[];
        }>;
        const resourceConditions = (conditions as any)[resourceType] ?? {};
        const roleEntries: ResourceRole[] = roleDefs.map((role) => ({
          name: role.name,
          actions: [...role.actions],
          condition: async (userId: string, resourceId: string) => {
            const cond = resourceConditions[role.name] as
              | RelationshipFunction
              | undefined;
            if (!cond) return false;
            return cond(userId, resourceId);
          },
        }));
        (acc as any)[resourceType] = { actions, roles: roleEntries };
        return acc;
      }, {} as Policies);

      return policy;
    }

    /**
     * Checks whether a user has a specific role for a given resource at runtime.
     *
     * This function performs validation and then delegates to the runtime checker.
     * It ensures type safety by constraining the role parameter to only valid roles
     * that have been defined for the specified resource type.
     *
     * @example
     * ```typescript
     * // Check if user can edit a document
     * const canEdit = await accessControl.checkRole('documents', 'editor', userId, documentId);
     *
     * // Check if user can manage a project
     * const canManage = await accessControl.checkRole('projects', 'owner', userId, projectId);
     * ```
     *
     * @template K - Resource type key (must exist in TResources)
     * @template R - Role name (must exist for the specified resource type)
     * @param resourceType - The type of resource to check permissions for
     * @param roleName - The role to check for the user
     * @param userId - ID of the user to check permissions for
     * @param resourceId - ID of the specific resource instance
     * @returns Promise resolving to true if user has the role, false otherwise
     * @throws Error if resource type or role name is not recognized
     */
    async function checkRole<
      K extends keyof TResources & keyof RoleNameMap & string,
      R extends RoleNameMap[K],
    >(
      resourceType: K,
      roleName: R,
      userId: string,
      resourceId: string
    ): Promise<boolean> {
      if (!(resourceType in resources)) {
        throw new Error(`Unknown resource '${resourceType}'`);
      }
      const definedRoles = new Set(
        (roles as any)[resourceType]?.map((r: any) => r.name) ?? []
      );
      if (!definedRoles.has(roleName)) {
        throw new Error(
          `Unknown role '${String(roleName)}' for resource '${String(resourceType)}'`
        );
      }
      return runtimeCheckRole(
        resourceType as string,
        roleName as string,
        userId,
        resourceId
      );
    }

    return { roleConditions, checkRole } as const;
  }

  return { resourceRoles } as const;
}
