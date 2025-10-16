import type { Policies } from "./types";
import NodeCache from "node-cache";

/**
 * Global policy engine instance shared across the application.
 *
 * This singleton instance is used by the authorization checking functions
 * in check.ts to perform permission evaluations. It should be initialized
 * once during application startup using initializePolicyEngine().
 *
 * @example
 * ```typescript
 * import { initializePolicyEngine } from './policy-engine';
 * import { accessControl } from './builder';
 *
 * // Initialize the policy engine with built policies
 * const policies = accessControl.roleConditions({...});
 * const engine = initializePolicyEngine(policies);
 * ```
 */
export let policyEngineInstance: PolicyEngine | null = null;

/**
 * Initializes and returns the global policy engine instance.
 *
 * This function creates a new PolicyEngine with the provided policies and caching configuration,
 * sets it as the global instance, and returns it for use by other parts of the application.
 *
 * @example
 * ```typescript
 * import { initializePolicyEngine } from './policy-engine';
 * import { createAccessControl } from './builder';
 *
 * const accessControl = createAccessControl({
 *   documents: ['read', 'write', 'delete'] as const,
 * }).roleConditions({...});
 *
 * // Initialize with caching enabled (default)
 * const engine = initializePolicyEngine(accessControl);
 *
 * // Or initialize with caching disabled
 * const engineNoCache = initializePolicyEngine(accessControl, false);
 * ```
 *
 * @param policies - The authorization policies object containing resources, roles, and conditions
 * @param cachingEnabled - Whether to enable response caching (default: true)
 * @returns The initialized PolicyEngine instance
 */
export function initializePolicyEngine(policies: Policies, cachingEnabled: boolean = true): PolicyEngine {
  policyEngineInstance = new PolicyEngine(policies, cachingEnabled);

  return policyEngineInstance;
}

/**
 * Core policy engine for evaluating authorization permissions in a Zanzibar-based system.
 *
 * The PolicyEngine handles runtime permission checking with optional caching support.
 * It evaluates whether users have specific roles or can perform specific actions on resources
 * based on the configured policies and role conditions.
 *
 * @example
 * ```typescript
 * const engine = new PolicyEngine(policies, true);
 *
 * // Check if user has a role
 * const roleResult = await engine.checkRole('documents', 'editor', userId, docId);
 * console.log(roleResult.allowed); // true/false
 *
 * // Check if user can perform an action
 * const actionResult = await engine.check(userId, 'write', 'documents', docId);
 * console.log(actionResult.allowed); // true/false
 * ```
 */
export class PolicyEngine {
  private policies: Policies;
  private cache: NodeCache;
  private cachingEnabled: boolean;

  /**
   * Creates a new PolicyEngine instance with the specified policies and caching configuration.
   *
   * @param policies - The authorization policies containing resource definitions, roles, and conditions
   * @param cachingEnabled - Whether to enable response caching for improved performance (default: true)
   *
   * @example
   * ```typescript
   * const engine = new PolicyEngine(policies, true); // With caching
   * const engineNoCache = new PolicyEngine(policies, false); // Without caching
   * ```
   */
  constructor(policies: Policies, cachingEnabled: boolean = true) {
    this.policies = policies;
    this.cache = new NodeCache({ stdTTL: 300, checkperiod: 60 }); // 5 minutes TTL
    this.cachingEnabled = cachingEnabled;
  }

  /**
   * Checks whether a user has a specific role for a given resource.
   *
   * This method evaluates the role condition function associated with the specified role
   * to determine if the user should be granted that role for the particular resource instance.
   *
   * @example
   * ```typescript
   * // Check if user has editor role for a document
   * const result = await engine.checkRole('documents', 'editor', userId, documentId);
   * if (result.allowed) {
   *   console.log('User can edit this document');
   * } else {
   *   console.log('User cannot edit this document');
   * }
   * ```
   *
   * @param resourceType - The type of resource to check permissions for (e.g., 'documents', 'projects')
   * @param roleName - The name of the role to check (e.g., 'editor', 'viewer', 'admin')
   * @param userId - The ID of the user to check permissions for
   * @param resourceId - The ID of the specific resource instance
   * @returns Promise resolving to an object with `allowed` boolean and descriptive `message`
   */
  async checkRole(
    resourceType: string,
    roleName: string,
    userId: string,
    resourceId: string
  ): Promise<{ allowed: boolean; message: string }> {
    const cacheKey = `checkRole:${resourceType}:${roleName}:${userId}:${resourceId}`;

    if (this.cachingEnabled) {
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return cached as { allowed: boolean; message: string };
      }
    }

    const resource = this.policies[resourceType];
    if (!resource) {
      const result = {
        allowed: false,
        message: `Unknown resource type '${resourceType}'`,
      };
      if (this.cachingEnabled) this.cache.set(cacheKey, result);
      return result;
    }
    const role = resource.roles.find((r) => r.name === roleName);
    if (!role) {
      const result = {
        allowed: false,
        message: `Unknown role '${roleName}' for resource '${resourceType}'`,
      };
      if (this.cachingEnabled) this.cache.set(cacheKey, result);
      return result;
    }
    const allowed = await role.condition(userId, resourceId);
    const result = {
      allowed,
      message: allowed
        ? `Role '${roleName}' allowed on ${resourceType}`
        : `Role '${roleName}' denied on ${resourceType}`,
    };
    if (this.cachingEnabled) this.cache.set(cacheKey, result);
    return result;
  }

  /**
   * Checks whether a user can perform a specific action on a resource.
   *
   * This method iterates through all roles defined for the resource type and checks
   * if any role that includes the specified action has a condition that allows the user
   * to perform that action on the particular resource instance.
   *
   * @example
   * ```typescript
   * // Check if user can write to a document
   * const result = await engine.check(userId, 'write', 'documents', documentId);
   * if (result.allowed) {
   *   console.log('User can write to this document');
   * } else {
   *   console.log('User cannot write to this document');
   * }
   *
   * // Check if user can delete a project
   * const deleteResult = await engine.check(userId, 'delete', 'projects', projectId);
   * ```
   *
   * @param userId - The ID of the user to check permissions for
   * @param action - The specific action to check (e.g., 'read', 'write', 'delete', 'view', 'edit')
   * @param resourceType - The type of resource to check permissions for (e.g., 'documents', 'projects')
   * @param resourceId - The ID of the specific resource instance
   * @returns Promise resolving to an object with `allowed` boolean and descriptive `message`
   */
  async check(
    userId: string,
    action: string,
    resourceType: string,
    resourceId: string
  ): Promise<{ allowed: boolean; message: string }> {
    const cacheKey = `check:${userId}:${action}:${resourceType}:${resourceId}`;

    if (this.cachingEnabled) {
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return cached as { allowed: boolean; message: string };
      }
    }

    const resource = this.policies[resourceType];
    if (!resource) {
      const result = {
        allowed: false,
        message: `Unknown resource type '${resourceType}'`,
      };
      if (this.cachingEnabled) this.cache.set(cacheKey, result);
      return result;
    }
    if (!resource.actions.includes(action)) {
      const result = {
        allowed: false,
        message: `Unknown action '${action}' for resource '${resourceType}'`,
      };
      if (this.cachingEnabled) this.cache.set(cacheKey, result);
      return result;
    }
    for (const role of resource.roles) {
      if (!role.actions.includes(action)) continue;
      const allowed = await role.condition(userId, resourceId);
      if (allowed) {
        const result = {
          allowed: true,
          message: `Action '${action}' allowed on ${resourceType}`,
        };
        if (this.cachingEnabled) this.cache.set(cacheKey, result);
        return result;
      }
    }
    const result = {
      allowed: false,
      message: `Action '${action}' denied on ${resourceType}`,
    };
    if (this.cachingEnabled) this.cache.set(cacheKey, result);
    return result;
  }
}
