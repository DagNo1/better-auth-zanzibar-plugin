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
        return await acRoles.checkRole(
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
        return await acRoles.checkRole(
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
        return await acRoles.checkRole(
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
        return await acRoles.checkRole(
          "folder",
          "owner",
          userId,
          file.folderId
        );
      }
      return false;
    },
    viewer: async (userId: string, resourceId: string) => {
      const file = await getFileById(resourceId);
      if (file?.folderId) {
        return await acRoles.checkRole(
          "folder",
          "viewer",
          userId,
          file.folderId
        );
      }
      return false;
    },
    sharer: async (userId: string, resourceId: string) => {
      const file = await getFileWithFolder(resourceId);
      const projectId = file?.folder?.projectId ?? null;
      if (projectId) {
        return await acRoles.checkRole("project", "owner", userId, projectId);
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
- **Traversal**: inside a role condition, calling `checkRole("A", role, userId, relatedId)` moves along an edge from one node to another and reuses the policy defined for that target node.
- **Result**: complex, multi-hop permission logic emerges by composing small role checks, without hardcoding cross-resource permissions in one place.

## Client usage (Better Auth client)

```ts
import { ZanzibarClientPlugin } from "better-auth-zanzibar-plugin";

const authClient = betterAuthClient({ plugins: [ZanzibarClientPlugin] });

// Use the plugin via the zanzibar namespace
const canRead = await authClient.zanzibar.check(
  "user-1",
  "read",
  "documents",
  "doc-1"
);
const isEditor = await authClient.zanzibar.checkRole(
  "documents",
  "editor",
  "user-1",
  "doc-1"
);
```