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
  const pluginId = "zanzibar";

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
       * @throws INTERNAL_SERVER_ERROR if Zanzibar is not initialized with policies
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
          // The body is already parsed and validated by Better Auth
          const { action, resourceType, resourceId } = ctx.body;
          const userId = ctx.context.session?.user.id;

          if (!policyEngineInstance) {
            throw ctx.error("INTERNAL_SERVER_ERROR", {
              message: "Zanzibar not initialized with policies",
            });
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
        }
      ),
      /**
       * POST endpoint for checking a SINGLE role.
       *
       * Use this endpoint to check if a user has ONE specific role on a resource.
       * For checking multiple roles or permissions, use the `hasPermissions` endpoint.
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
       * @throws INTERNAL_SERVER_ERROR if Zanzibar is not initialized with policies
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
          const { resourceType, roleName, resourceId } = ctx.body;
          const userId = ctx.context.session?.user.id;

          if (!policyEngineInstance) {
            throw ctx.error("INTERNAL_SERVER_ERROR", {
              message: "Zanzibar not initialized with policies",
            });
          }

          const allowed = await policyEngineInstance.hasRole(
            resourceType,
            roleName,
            userId,
            resourceId
          );
          return ctx.json({ ...allowed });
        }
      ),
      /**
       * POST endpoint for checking permissions across multiple resources.
       *
       * This endpoint allows you to perform multiple permission checks with custom names,
       * where each check can target different resource types, actions, and resource IDs.
       * This is the most flexible permission checking endpoint.
       *
       * @example
       * ```typescript
       * // Check various permissions with custom names
       * const response = await fetch('/api/auth/zanzibar/has-permissions', {
       *   method: 'POST',
       *   headers: { 'Content-Type': 'application/json' },
       *   body: JSON.stringify({
       *     checks: {
       *       project: {
       *         resourceType: 'project',
       *         actions: ['create', 'update', 'delete'],
       *         resourceId: 'project-123'
       *       },
       *       folderCreate: {
       *         resourceType: 'folder',
       *         action: 'create',
       *         resourceId: 'folder-456'
       *       },
       *       folderEdit: {
       *         resourceType: 'folder',
       *         action: 'edit',
       *         resourceId: 'folder-456'
       *       }
       *     }
       *   })
       * });
       *
       * const result = await response.json();
       * console.log(result.project.allowed); // false
       * console.log(result.project.results); // { create: true, update: true, delete: false }
       * console.log(result.folderCreate.allowed); // true
       * ```
       *
       * Request body schema:
       * - `checks`: Record<string, { resourceType: string, action?: string, actions?: string[], resourceId: string }>
       *
       * Response format:
       * ```typescript
       * Record<string, {
       *   allowed: boolean,
       *   message: string,
       *   results?: Record<string, boolean>  // Only present for multi-action checks
       * }>
       * ```
       *
       * @throws INTERNAL_SERVER_ERROR if Zanzibar is not initialized with policies
       */
      hasPermissions: createAuthEndpoint(
        "/zanzibar/has-permissions",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            checks: z.record(
              z.string(),
              z.object({
                resourceType: z.string(),
                action: z.string().optional(),
                actions: z.array(z.string()).optional(),
                resourceId: z.string(),
              })
            ),
          }),
        },
        async (ctx) => {
          const { checks } = ctx.body;
          const userId = ctx.context.session?.user.id;

          if (!policyEngineInstance) {
            throw ctx.error("INTERNAL_SERVER_ERROR", {
              message: "Zanzibar not initialized with policies",
            });
          }

          const result = await policyEngineInstance.hasPermissions(
            userId,
            checks
          );
          return ctx.json(result);
        }
      ),
    },
  } satisfies BetterAuthPlugin;
};
