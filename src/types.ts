/**
 * A function that determines whether a relationship exists between a user and a resource.
 * Used to evaluate complex authorization conditions beyond simple role-based access.
 * @param userId - The unique identifier of the user
 * @param resourceId - The unique identifier of the resource
 * @returns Promise<boolean> - True if the relationship exists, false otherwise
 */
export type RelationshipFunction = (
  userId: string,
  resourceId: string
) => Promise<boolean>;

/**
 * Defines a role within a resource type, including the actions the role can perform
 * and the condition function that determines if a user has this role.
 */
export interface ResourceRole {
  /** The unique name of the role */
  name: string;
  /** Array of action names this role is permitted to perform */
  actions: readonly string[];
  /** Function that evaluates whether a user has this role for a specific resource */
  condition: RelationshipFunction;
}

/**
 * Defines the complete authorization configuration for a resource type,
 * including all available actions and roles.
 */
export interface ResourceDefinition {
  /** Array of all action names available for this resource type */
  actions: readonly string[];
  /** Array of all roles defined for this resource type */
  roles: readonly ResourceRole[];
}

/**
 * A collection of resource definitions keyed by resource type.
 * This forms the complete authorization policy configuration.
 */
export interface Policies {
  /** Maps resource type names to their definitions */
  [resourceType: string]: ResourceDefinition;
}

/*
Generic builder to enforce compile-time consistency between
resource types, actions, roles and role-conditions.
*/

/**
 * Defines the shape of resources and their available actions.
 * Used as a constraint type to ensure consistency between resource definitions.
 */
export type ResourcesShape = Record<string, readonly string[]>;

/**
 * Defines the shape of roles for each resource type, with compile-time safety.
 * Ensures that roles are only defined for resources that exist and actions are valid.
 * @template TResources - The resource shape this role configuration applies to
 */
export type RolesShape<TResources extends ResourcesShape> = {
  readonly [R in keyof TResources]?: ReadonlyArray<{
    /** The unique name of the role */
    name: string;
    /** Array of action names this role can perform */
    actions: readonly string[];
  }>;
};

/**
 * Defines the shape of condition functions for role assignments.
 * Provides compile-time safety for role-condition mappings.
 * @template TResources - The resource shape this applies to
 * @template TRoles - The roles shape that defines available roles
 */
export type ConditionsShape<
  TResources extends ResourcesShape,
  TRoles extends RolesShape<TResources>,
> = {
  readonly [R in keyof TResources]?: Partial<
    Record<
      Extract<
        TRoles[R] extends ReadonlyArray<infer RR>
          ? RR extends { name: infer N }
            ? N
            : never
          : never,
        string
      >,
      RelationshipFunction
    >
  >;
};
