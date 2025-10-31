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
 * import { ZanzibarClientPlugin } from "better-auth-zanzibar-plugin";
 *
 * const authClient = betterAuthClient({ plugins: [ZanzibarClientPlugin] });
 *
 * // Check a single role
 * const isEditor = await authClient.zanzibar.hasRole(
 *   "documents",
 *   "editor",
 *   "user-1",
 *   "doc-1"
 * );
 *
 * // Check a single permission
 * const canRead = await authClient.zanzibar.hasPermission(
 *   "user-1",
 *   "read",
 *   "documents",
 *   "doc-1"
 * );
 *
 * // Check multiple permissions with custom names
 * const result = await authClient.zanzibar.hasPermissions(
 *   "user-1",
 *   {
 *     projectPermissions: {
 *       resourceType: "project",
 *       actions: ["create", "update"],
 *       resourceId: "project-123"
 *     },
 *     folderAccess: {
 *       resourceType: "folder",
 *       action: "edit",
 *       resourceId: "folder-456"
 *     }
 *   }
 * );
 * ```
 *
 * @returns A client plugin object that satisfies BetterAuthClientPlugin interface
 */
export const ZanzibarClientPlugin = () => {
  return {
    id: "zanzibar",
    $InferServerPlugin: {} as ReturnType<typeof ZanzibarPlugin>,
  } satisfies BetterAuthClientPlugin;
};
