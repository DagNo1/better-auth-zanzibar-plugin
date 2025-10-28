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
       * POST endpoint for checking a SINGLE permission.
       *
       * Use this endpoint to check if a user has permission to perform ONE specific action
       * on a resource. For checking multiple permissions at once, use the `hasPermissions` endpoint.
       *
       * @example
       * ```typescript
       * // Check a single permission
       * const response = await fetch('/api/auth/zanzibar/has-permission', {
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
       * Error responses (always returns { allowed: false, message: string }):
       * - `500`: "Zanzibar not initialized with policies" - Policy engine not ready
       * - `500`: "Internal server error" - Unexpected server error
       */
      hasPermission: createAuthEndpoint(
        "/zanzibar/has-permission",
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
                {
                  allowed: false,
                  message: "Zanzibar not initialized with policies",
                },
                { status: 500 }
              );
            }

            const allowed = await policyEngineInstance.hasPermission(
              userId,
              action,
              resourceType,
              resourceId
            );
            return ctx.json({
              ...allowed,
            });
          } catch (error) {
            console.error("Zanzibar hasPermission error:", error);
            return ctx.json(
              { allowed: false, message: "Internal server error" },
              { status: 500 }
            );
          }
        }
      ),
      /**
       * POST endpoint for checking MULTIPLE permissions at once.
       *
       * Use this endpoint to efficiently check multiple permissions in a single request.
       * This is useful when you need to verify several permissions simultaneously.
       * The endpoint returns `allowed: true` only if ALL permissions are granted.
       *
       * Note: This differs from `hasPermission` endpoint which checks only a single permission.
       *
       * @example
       * ```typescript
       * // Check multiple permissions across resource types
       * const response = await fetch('/api/auth/zanzibar/has-permissions', {
       *   method: 'POST',
       *   headers: { 'Content-Type': 'application/json' },
       *   body: JSON.stringify({
       *     permissions: {
       *       project: ['create', 'update', 'delete'],
       *       folder: ['read', 'share']
       *     },
       *     resourceId: 'project-123'
       *   })
       * });
       *
       * const result = await response.json();
       * console.log(result.allowed); // true only if ALL permissions granted
       * console.log(result.results);
       * // {
       * //   project: { create: true, update: true, delete: false },
       * //   folder: { read: true, share: true }
       * // }
       * ```
       *
       * Request body schema:
       * - `permissions`: Record<string, string[]> - Object mapping resource types to arrays of actions
       * - `resourceId`: string - The specific resource instance ID
       *
       * Response format:
       * ```typescript
       * {
       *   allowed: boolean,     // true only if ALL permissions are granted
       *   message: string,      // Human-readable explanation
       *   results: Record<string, Record<string, boolean>>  // Detailed results per permission
       * }
       * ```
       */
      hasPermissions: createAuthEndpoint(
        "/zanzibar/has-permissions",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            permissions: z.record(z.string(), z.array(z.string())),
            resourceId: z.string(),
          }),
        },
        async (ctx) => {
          try {
            const { permissions, resourceId } = ctx.body;
            const userId = ctx.context.session?.user.id;

            if (!policyEngineInstance) {
              return ctx.json(
                {
                  allowed: false,
                  message: "Zanzibar not initialized with policies",
                },
                { status: 500 }
              );
            }

            const result = await policyEngineInstance.hasMultiplePermissions(
              userId,
              permissions as Record<string, string[]>,
              resourceId
            );
            return ctx.json(result);
          } catch (error) {
            console.error("Zanzibar hasPermissions error:", error);
            return ctx.json(
              { allowed: false, message: "Internal server error" },
              { status: 500 }
            );
          }
        }
      ),
      /**
       * POST endpoint for checking a SINGLE role.
       *
       * Use this endpoint to check if a user has ONE specific role on a resource.
       * For checking multiple roles at once, use the `hasRoles` endpoint.
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
       *
       * Error responses (always returns { allowed: false, message: string }):
       * - `500`: "Zanzibar not initialized with policies" - Policy engine not ready
       * - `500`: "Internal server error" - Unexpected server error
       */
      hasRole: createAuthEndpoint(
        "/zanzibar/has-role",
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
            const { resourceType, roleName, resourceId } = ctx.body;
            const userId = ctx.context.session?.user.id;

            if (!policyEngineInstance) {
              return ctx.json(
                {
                  allowed: false,
                  message: "Zanzibar not initialized with policies",
                },
                { status: 500 }
              );
            }

            const allowed = await policyEngineInstance.hasRole(
              resourceType,
              roleName,
              userId,
              resourceId
            );
            return ctx.json({ ...allowed });
          } catch (error) {
            console.error("Zanzibar hasRole error:", error);
            return ctx.json(
              { allowed: false, message: "Internal server error" },
              { status: 500 }
            );
          }
        }
      ),
      /**
       * POST endpoint for checking MULTIPLE roles at once.
       *
       * Use this endpoint to efficiently check multiple roles in a single request.
       * This is useful when you need to verify several roles simultaneously.
       * The endpoint returns `allowed: true` only if ALL roles are granted.
       *
       * Note: This differs from `hasRole` endpoint which checks only a single role.
       *
       * @example
       * ```typescript
       * // Check multiple roles across resource types
       * const response = await fetch('/api/auth/zanzibar/has-roles', {
       *   method: 'POST',
       *   headers: { 'Content-Type': 'application/json' },
       *   body: JSON.stringify({
       *     roles: {
       *       project: ['owner', 'editor'],
       *       folder: ['viewer']
       *     },
       *     resourceId: 'project-123'
       *   })
       * });
       *
       * const result = await response.json();
       * console.log(result.allowed); // true only if ALL roles granted
       * console.log(result.results);
       * // {
       * //   project: { owner: true, editor: false },
       * //   folder: { viewer: true }
       * // }
       * ```
       *
       * Request body schema:
       * - `roles`: Record<string, string[]> - Object mapping resource types to arrays of role names
       * - `resourceId`: string - The specific resource instance ID
       *
       * Response format:
       * ```typescript
       * {
       *   allowed: boolean,     // true only if ALL roles are granted
       *   message: string,      // Human-readable explanation
       *   results: Record<string, Record<string, boolean>>  // Detailed results per role
       * }
       * ```
       */
      hasRoles: createAuthEndpoint(
        "/zanzibar/has-roles",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            roles: z.record(z.string(), z.array(z.string())),
            resourceId: z.string(),
          }),
        },
        async (ctx) => {
          try {
            const { roles, resourceId } = ctx.body;
            const userId = ctx.context.session?.user.id;

            if (!policyEngineInstance) {
              return ctx.json(
                {
                  allowed: false,
                  message: "Zanzibar not initialized with policies",
                },
                { status: 500 }
              );
            }

            const result = await policyEngineInstance.hasMultipleRoles(
              userId,
              roles as Record<string, string[]>,
              resourceId
            );
            return ctx.json(result);
          } catch (error) {
            console.error("Zanzibar hasRoles error:", error);
            return ctx.json(
              { allowed: false, message: "Internal server error" },
              { status: 500 }
            );
          }
        }
      ),
    },
  } satisfies BetterAuthPlugin;
};
