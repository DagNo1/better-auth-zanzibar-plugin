import { type BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { initializePolicyEngine, policyEngineInstance } from "./policy-engine";
import type { Policies } from "./types";
import { z } from "zod";

/**
 * Creates a Zanzibar authorization plugin for Better Auth that provides server-side authorization endpoints.
 *
 * This plugin integrates the Zanzibar policy engine with Better Auth to provide HTTP endpoints
 * for authorization checking. It automatically initializes the policy engine on first use and
 * provides a REST API for checking permissions.
 *
 * @example
 * ```typescript
 * import { ZanzibarPlugin } from './zanzibar/server';
 * import { createAccessControl } from './zanzibar/builder';
 *
 * // Define your authorization policies
 * const accessControl = createAccessControl({
 *   documents: ['read', 'write', 'delete'] as const,
 *   projects: ['view', 'edit', 'manage'] as const,
 * }).roleConditions({...});
 *
 * // Create the plugin with your policies
 * const zanzibarPlugin = ZanzibarPlugin(accessControl);
 *
 * // Use in your Better Auth configuration
 * export const auth = betterAuth({
 *   plugins: [zanzibarPlugin],
 *   // ... other auth config
 * });
 * ```
 *
 * @example
 * ```typescript
 * const zanzibarPlugin = ZanzibarPlugin(policies, false);
 * ```
 *
 * @param policies - The authorization policies object defining resources, roles, and conditions
 * @param cachingEnabled - Whether to enable caching of authorization results (default: false)
 * @returns A Better Auth plugin with Zanzibar authorization endpoints
 */
export const ZanzibarPlugin = (
  policies: Policies,
  cachingEnabled: boolean = false
) => {
  const pluginId = "zanzibar-plugin";

  if (!policyEngineInstance) {
    initializePolicyEngine(policies, cachingEnabled);
  }

  return {
    id: pluginId,
    endpoints: {
      /**
       * POST endpoint for checking authorization permissions.
       *
       * This endpoint allows authenticated users to check if they can perform specific actions
       * on resources. The endpoint validates the request, extracts user session information,
       * and uses the policy engine to evaluate permissions.
       *
       * @example
       * ```typescript
       * // Client-side usage with fetch
       * const response = await fetch('/api/auth/zanzibar/check', {
       *   method: 'POST',
       *   headers: { 'Content-Type': 'application/json' },
       *   body: JSON.stringify({
       *     action: 'write',
       *     resourceType: 'documents',
       *     resourceId: 'doc-123'
       *   })
       * });
       *
       * const result = await response.json();
       * console.log(result.allowed); // true/false
       * console.log(result.message); // "Action 'write' allowed on documents"
       * ```
       *
       * @example
       * ```typescript
       * // Using with the Zanzibar client plugin
       * import { ZanzibarClientPlugin } from './zanzibar/client';
       *
       * const client = betterAuthClient({
       *   plugins: [ZanzibarClientPlugin],
       * });
       *
       * const auth = client.useZanzibarPlugin();
       * const result = await auth.check(userId, 'read', 'documents', 'doc-123');
       * ```
       *
       * Request body schema:
       * - `action`: string - The action to check (e.g., 'read', 'write', 'delete')
       * - `resourceType`: string - The type of resource (e.g., 'documents', 'projects')
       * - `resourceId`: string - The specific resource instance ID
       *
       * Response format:
       * ```typescript
       * {
       *   allowed: boolean,     // Whether the action is permitted
       *   message: string       // Human-readable explanation
       * }
       * ```
       *
       * Error responses:
       * - `500`: "Zanzibar not initialized with policies" - Policy engine not ready
       * - `500`: "Internal server error" - Unexpected server error
       */
      check: createAuthEndpoint(
        "/zanzibar/check",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            action: z.string(),
            resourceType: z.string(),
            resourceId: z.string(),
          }),
        },
        async (ctx) => {
          try {
            // The body is already parsed and validated by Better Auth
            const { action, resourceType, resourceId } = ctx.body;
            const userId = ctx.context.session?.user.id;

            if (!policyEngineInstance) {
              return ctx.json(
                { error: "Zanzibar not initialized with policies" },
                { status: 500 }
              );
            }

            const allowed = await policyEngineInstance.check(
              userId,
              action,
              resourceType,
              resourceId
            );
            return ctx.json({
              ...allowed,
            });
          } catch (error) {
            console.error("Zanzibar check error:", error);
            return ctx.json(
              { error: "Internal server error" },
              { status: 500 }
            );
          }
        }
      ),
      /**
       * POST endpoint for checking whether the authenticated user has a specific role
       * for a given resource instance.
       *
       * Request body schema:
       * - `resourceType`: string - The type of resource (e.g., 'documents', 'projects')
       * - `roleName`: string - The name of the role to check (e.g., 'editor', 'viewer')
       * - `resourceId`: string - The specific resource instance ID
       *
       * Response format:
       * ```typescript
       * { allowed: boolean, message: string }
       * ```
       */
      checkRole: createAuthEndpoint(
        "/zanzibar/check-role",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            roleName: z.string(),
            resourceId: z.string(),
          }),
        },
        async (ctx) => {
          try {
            // The body is already parsed and validated by Better Auth
            const { resourceType, roleName, resourceId } = ctx.body;
            const userId = ctx.context.session?.user.id;

            if (!policyEngineInstance) {
              return ctx.json(
                { error: "Zanzibar not initialized with policies" },
                { status: 500 }
              );
            }

            const allowed = await policyEngineInstance.checkRole(
              resourceType,
              roleName,
              userId,
              resourceId
            );
            return ctx.json({ ...allowed });
          } catch (error) {
            console.error("Zanzibar checkRole error:", error);
            return ctx.json(
              { error: "Internal server error" },
              { status: 500 }
            );
          }
        }
      ),
    },
  } satisfies BetterAuthPlugin;
};
