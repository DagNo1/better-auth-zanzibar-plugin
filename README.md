# Better Auth Zanzibar Plugin

A small, framework-agnostic Zanzibar-style authorization helper designed to plug into Better Auth.

This plugin introduces a Relationship-Based Access Control (ReBAC) model inspired by Google Zanzibar. Unlike plain RBAC, ReBAC makes authorization dynamic and context-aware by evaluating relationships between entities (e.g., a user can edit a file because they are an editor on its project or a collaborator on its folder).

- Purpose: complement existing role-based setups with fine-grained, relationship-driven permissions.
- What it builds on: Better Auth’s plugin system (server + client) while letting you keep your own data layer (ORM/SQL/HTTP).
- Problems it solves:
  - Resource-level, relationship-based checks across hierarchies (project → folder → file)
  - Delegation and sharing (grant access to specific users/groups)
  - Declarative policies instead of ad-hoc permission code
  - Composable checks that traverse relationships (graph-style)

## Install

```bash
npm install better-auth-zanzibar-plugin
```

## Quick start

```ts
import { createAccessControl } from "better-auth-zanzibar-plugin";
import { ZanzibarPlugin } from "better-auth-zanzibar-plugin";

// 1) Define resources and roles
const resources = {
  project: ["delete", "read", "edit", "share"],
  folder: ["delete", "read", "edit", "share"],
  file: ["delete", "read", "edit", "share"],
} as const;

const ac = createAccessControl(resources);

const acRoles = ac.resourceRoles({
  project: [
    { name: "owner", actions: ["delete", "read", "edit", "share"] },
    { name: "editor", actions: ["read", "edit"] },
    { name: "viewer", actions: ["read"] },
  ],
  folder: [
    { name: "owner", actions: ["delete", "read", "edit", "share"] },
    { name: "viewer", actions: ["read"] },
    { name: "sharer", actions: ["read", "share"] },
  ],
  file: [
    { name: "owner", actions: ["delete", "read", "edit", "share"] },
    { name: "viewer", actions: ["read"] },
    { name: "sharer", actions: ["read", "share"] },
  ],
} as const);

// 2) Add role conditions
const policies = acRoles.roleConditions({
  project: {
    owner: async (userId: string, resourceId: string) => {
      return await isProjectOwner(userId, resourceId);
    },
    editor: async (userId: string, resourceId: string) => {
      return await isProjectMember(userId, resourceId);
    },
    viewer: async (userId: string, resourceId: string) => {
      return await canViewProject(userId, resourceId);
    },
  },
  folder: {
    owner: async (userId: string, resourceId: string) => {
      const folder = await getFolderById(resourceId);
      if (folder?.projectId) {
        return await acRoles.hasRole(
          "project",
          "owner",
          userId,
          folder.projectId
        );
      }
      return false;
    },
    viewer: async (userId: string, resourceId: string) => {
      const folder = await getFolderById(resourceId);
      if (folder?.projectId) {
        return await acRoles.hasRole(
          "project",
          "viewer",
          userId,
          folder.projectId
        );
      }
      return false;
    },
    sharer: async (userId: string, resourceId: string) => {
      const folder = await getFolderById(resourceId);
      if (folder?.projectId) {
        return await acRoles.hasRole(
          "project",
          "owner",
          userId,
          folder.projectId
        );
      }
      return false;
    },
  },
  file: {
    owner: async (userId: string, resourceId: string) => {
      const file = await getFileById(resourceId);
      if (file?.folderId) {
        return await acRoles.hasRole("folder", "owner", userId, file.folderId);
      }
      return false;
    },
    viewer: async (userId: string, resourceId: string) => {
      const file = await getFileById(resourceId);
      if (file?.folderId) {
        return await acRoles.hasRole("folder", "viewer", userId, file.folderId);
      }
      return false;
    },
    sharer: async (userId: string, resourceId: string) => {
      const file = await getFileWithFolder(resourceId);
      const projectId = file?.folder?.projectId ?? null;
      if (projectId) {
        return await acRoles.hasRole("project", "owner", userId, projectId);
      }
      return false;
    },
  },
} as const);

// 3) Create Better Auth plugin
export const zanzibar = ZanzibarPlugin(policies);
```

### What to write inside role condition functions

> The helper functions used in the code examples above (like `isProjectOwner`, `getFolderById`, etc.) are for illustration only.
> Replace them with your actual database queries, ORM models, HTTP requests, or other application-specific logic as needed.
> Role condition functions should implement your business rules for checking relationships or permissions—adapt these to fit your own data structures and infrastructure.

### Why this behaves like a graph

- **Nodes**: concrete resource instances (e.g., a specific `project`, `folder`, or `file`).
- **Edges**: relationships between instances (e.g., `folder.projectId`, `file.folderId`).
- **Traversal**: inside a role condition, calling `hasRole("A", role, userId, relatedId)` moves along an edge from one node to another and reuses the policy defined for that target node.
- **Result**: complex, multi-hop permission logic emerges by composing small role checks, without hardcoding cross-resource permissions in one place.

## Client usage (Better Auth client)

```ts
import { ZanzibarClientPlugin } from "better-auth-zanzibar-plugin";

const authClient = betterAuthClient({ plugins: [ZanzibarClientPlugin] });

// Check a SINGLE role (returns boolean)
const isEditor = await authClient.zanzibar.hasRole(
  "documents",
  "editor",
  userId,
  "doc-1"
);

// Check MULTIPLE roles at once (returns object with detailed results)
const roleResult = await authClient.zanzibar.hasRoles(
  userId,
  { project: ["owner", "editor"] },
  "project-123"
);
console.log(roleResult.allowed); // true only if ALL roles granted
console.log(roleResult.results); // { project: { owner: true, editor: false } }

// Check a SINGLE permission (returns boolean)
const canRead = await authClient.zanzibar.hasPermission(
  userId,
  "read",
  "documents",
  "doc-1"
);

// Check MULTIPLE permissions at once (returns object with detailed results)
const permResult = await authClient.zanzibar.hasPermissions(
  userId,
  { project: ["create", "update"] },
  "project-123"
);
console.log(permResult.allowed); // true only if ALL permissions granted
console.log(permResult.results); // { project: { create: true, update: false } }
```

## Server usage

### Option 1: Direct Function Imports

```ts
import {
  hasRole,
  hasPermission,
  hasNamedPermissions,
} from "better-auth-zanzibar-plugin";

// Check a SINGLE role (returns boolean)
const isOwner = await hasRole("project", "owner", userId, "project-123");

// Check a SINGLE permission (returns boolean)
const canDelete = await hasPermission(userId, "delete", "documents", "doc-1");

// Check MULTIPLE permissions/roles with custom names (most flexible)
const result = await hasNamedPermissions(userId, {
  projectPermissions: {
    resourceType: "project",
    actions: ["create", "update", "delete"],
    resourceId: "project-123",
  },
  folderRole: {
    resourceType: "folder",
    action: "edit",
    resourceId: "folder-456",
  },
});
console.log(result.projectPermissions.allowed); // false
console.log(result.projectPermissions.results); // { create: true, update: true, delete: false }
console.log(result.folderRole.allowed); // true
```

### Option 2: Better Auth API (Server Components)

```ts
import { auth } from "./auth"; // your Better Auth instance
import { headers } from "next/headers"; // or your framework's headers

// Check a SINGLE role
const roleResult = await auth.api.hasRole({
  headers: await headers(),
  body: {
    resourceType: "project",
    roleName: "owner",
    resourceId: "project-123",
  },
});
console.log(roleResult.allowed); // boolean
console.log(roleResult.message); // descriptive message

// Check a SINGLE permission
const permResult = await auth.api.hasPermission({
  headers: await headers(),
  body: {
    action: "delete",
    resourceType: "documents",
    resourceId: "doc-1",
  },
});
console.log(permResult.allowed); // boolean
console.log(permResult.message); // descriptive message
```

> **Note**: The Better Auth API automatically extracts the `userId` from the session via the `headers`. You don't need to pass it explicitly.

### Option 3: Named Permission Checks (Most Flexible)

Check multiple permissions across different resources with custom names:

```ts
import { hasNamedPermissions } from "better-auth-zanzibar-plugin";

const result = await hasNamedPermissions(userId, {
  project: {
    resourceType: "project",
    actions: ["create", "update", "delete"],
    resourceId: "project-123",
  },
  folderCreate: {
    resourceType: "folder",
    action: "create",
    resourceId: "folder-456",
  },
  folderEdit: {
    resourceType: "folder",
    action: "edit",
    resourceId: "folder-456",
  },
});

console.log(result.project.allowed); // false
console.log(result.project.results); // { create: true, update: true, delete: false }
console.log(result.folderCreate.allowed); // true
console.log(result.folderEdit.allowed); // true
```

Or with Better Auth API:

```ts
const result = await auth.api.hasNamedPermissions({
  headers: await headers(),
  body: {
    checks: {
      project: {
        resourceType: "project",
        actions: ["create", "update", "delete"],
        resourceId: "project-123",
      },
      folderCreate: {
        resourceType: "folder",
        action: "create",
        resourceId: "folder-456",
      },
      folderEdit: {
        resourceType: "folder",
        action: "edit",
        resourceId: "folder-456",
      },
    },
  },
});

console.log(result.project.allowed); // false
console.log(result.folderCreate.allowed); // true
```

## API Summary

### Single Checks (return boolean)

- **`hasRole`**: Check if user has a specific role on a resource
- **`hasPermission`**: Check if user has a specific permission on a resource

### Named Checks (most flexible - return detailed object per check)

- **`hasNamedPermissions`**: Check multiple permissions/roles across different resources with custom names - returns `Record<string, { allowed, message, results? }>`

### Server Endpoints

- `POST /zanzibar/has-role` - Check single role
- `POST /zanzibar/has-permission` - Check single permission
- `POST /zanzibar/has-named-permissions` - Check multiple named permissions across different resources
