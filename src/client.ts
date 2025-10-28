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
 * // Check multiple roles at once
 * const roleResult = await authClient.zanzibar.hasRoles(
 *   "user-1",
 *   { project: ["owner", "editor"] },
 *   "project-123"
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
 * // Check multiple permissions at once
 * const permResult = await authClient.zanzibar.hasPermissions(
 *   "user-1",
 *   { project: ["create", "update"] },
 *   "project-123"
 * );
 * ```
 *
 * @returns A client plugin object that satisfies BetterAuthClientPlugin interface
 */
export const ZanzibarClientPlugin = () => {
  return {
    id: "zanzibar-plugin",
    $InferServerPlugin: {} as ReturnType<typeof ZanzibarPlugin>,
  } satisfies BetterAuthClientPlugin;
};
