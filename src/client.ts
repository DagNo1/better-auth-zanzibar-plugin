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
 * // Use the plugin via the zanzibar namespace
 * const canRead = await authClient.zanzibar.check(
 *   "user-1",
 *   "read",
 *   "documents",
 *   "doc-1"
 * );
 * const isEditor = await authClient.zanzibar.checkRole(
 *   "documents",
 *   "editor",
 *   "user-1",
 *   "doc-1"
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
