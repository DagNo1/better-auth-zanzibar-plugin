import type { BetterAuthClientPlugin } from "better-auth/client";
import type { ZanzibarPlugin } from "./server";

/**
 * Creates a Zanzibar client plugin for Better Auth that provides authorization checking capabilities.
 *
 * This plugin enables client-side permission checking by making HTTP requests to the server's
 * Zanzibar authorization endpoints. It integrates with the Better Auth client to provide
 * seamless access control functionality.
 *
 * @example
 * ```typescript
 * import { ZanzibarClientPlugin } from './zanzibar/client';
 *
 * const client = betterAuthClient({
 *   plugins: [ZanzibarClientPlugin],
 *   // ... other client configuration
 * });
 *
 * // Use the plugin actions
 * const auth = client.useZanzibarPlugin();
 *
 * // Check if user can read a document
 * const canRead = await auth.check(userId, 'read', 'documents', documentId);
 *
 * // Check if user has editor role for a project
 * const isEditor = await auth.checkRole('projects', 'editor', userId, projectId);
 * ```
 *
 * @param client - The Better Auth client instance to extend with Zanzibar functionality
 * @returns A client plugin object that satisfies BetterAuthClientPlugin interface
 */
export const ZanzibarClientPlugin = (client: any) => {
  return {
    id: "zanzibar-plugin",
    $InferServerPlugin: {} as ReturnType<typeof ZanzibarPlugin>,
    /**
     * Provides authorization checking actions for the Zanzibar plugin.
     *
     * @returns Object containing `check` and `checkRole` methods for permission verification
     */
    getActions: () => ({
      /**
       * Checks whether a user can perform a specific action on a resource.
       *
       * This method makes an HTTP POST request to `/zanzibar/check` endpoint to verify
       * if the user has permission to perform the specified action on the given resource.
       *
       * @example
       * ```typescript
       * // Check if user can read a document
       * const canRead = await actions.check(userId, 'read', 'documents', documentId);
       *
       * // Check if user can delete a project
       * const canDelete = await actions.check(userId, 'delete', 'projects', projectId);
       *
       * // Check if user can write to a document
       * const canWrite = await actions.check(userId, 'write', 'documents', documentId);
       * ```
       *
       * @param userId - The ID of the user to check permissions for
       * @param action - The specific action to check (e.g., 'read', 'write', 'delete', 'view', 'edit')
       * @param resourceType - The type of resource to check permissions for (e.g., 'documents', 'projects')
       * @param resourceId - The ID of the specific resource instance
       * @returns Promise resolving to the server response containing permission result
       */
      check: async (
        userId: string,
        action: string,
        resourceType: string,
        resourceId: string
      ) => {
        return client.fetch("/zanzibar/check", {
          method: "POST",
          body: { userId, action, resourceType, resourceId },
        });
      },
      /**
       * Checks whether a user has a specific role for a given resource.
       *
       * This method makes an HTTP POST request to `/zanzibar/check-role` endpoint to verify
       * if the user has the specified role for the given resource type and instance.
       *
       * @example
       * ```typescript
       * // Check if user has editor role for a document
       * const isEditor = await actions.checkRole('documents', 'editor', userId, documentId);
       *
       * // Check if user has admin role for a project
       * const isAdmin = await actions.checkRole('projects', 'admin', userId, projectId);
       *
       * // Check if user has viewer role for a document
       * const isViewer = await actions.checkRole('documents', 'viewer', userId, documentId);
       * ```
       *
       * @param resourceType - The type of resource to check permissions for (e.g., 'documents', 'projects')
       * @param roleName - The name of the role to check (e.g., 'editor', 'viewer', 'admin', 'owner')
       * @param userId - The ID of the user to check permissions for
       * @param resourceId - The ID of the specific resource instance
       * @returns Promise resolving to the server response containing role permission result
       */
      checkRole: async (
        resourceType: string,
        roleName: string,
        userId: string,
        resourceId: string
      ) => {
        return client.fetch("/zanzibar/check-role", {
          method: "POST",
          body: { resourceType, roleName, userId, resourceId },
        });
      },
    }),
  } satisfies BetterAuthClientPlugin;
};

/**
 * Empty export to ensure this file is treated as a module.
 * This is necessary for proper TypeScript module resolution.
 */
export {};
