# Better Auth Zanzibar Plugin

A framework-agnostic Zanzibar-style authorization plugin for Better Auth that enables relationship-based access control (ReBAC).

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Usage Patterns](#usage-patterns)
7. [API Reference](#api-reference)

---

## Overview

### What is ReBAC?

**Relationship-Based Access Control (ReBAC)** makes authorization dynamic and context-aware by evaluating relationships between entities. Unlike plain RBAC (Role-Based Access Control), ReBAC allows you to express permissions like:

- _"A user can edit a file because they are an editor on its project"_
- _"A user can view a folder because they are a viewer on its parent project"_

### Key Features

- **Graph-based permissions** - Traverse relationships across resource hierarchies
- **Composable policies** - Small, reusable role checks that combine into complex permissions
- **Type-safe** - Full TypeScript inference for resources, roles, and actions
- **Framework-agnostic** - Works with any ORM, database, or API
- **Performance** - Optional caching for repeated authorization checks

### Problems It Solves

| Problem                    | Solution                                                            |
| -------------------------- | ------------------------------------------------------------------- |
| Resource-level permissions | Check permissions on specific instances (project-123, file-456)     |
| Hierarchical permissions   | Inherit permissions from parent resources (project → folder → file) |
| Permission delegation      | Grant access to specific users or groups dynamically                |
| Scattered permission logic | Centralize authorization in declarative policies                    |

---

## Installation

### Prerequisites

- **Node.js**: 18 or higher
- **Better Auth**: Any version

### Install the Plugin

```bash
npm install better-auth-zanzibar-plugin
```

### Install Peer Dependencies

```bash
npm install better-auth node-cache zod
```

---

## Core Concepts

### 1. Resources and Actions

**Resources** are the entities in your system. **Actions** are operations that can be performed on them.

```ts
const resources = {
  project: ["create", "read", "update", "delete", "share"],
  folder: ["read", "update", "delete"],
  file: ["read", "update", "delete"],
} as const;
```

### 2. Roles

**Roles** bundle multiple actions together for a resource.

```ts
{
  name: "editor",
  actions: ["read", "update"]  // Editors can read and update
}
```

### 3. Role Conditions

**Role conditions** are functions that determine if a user has a role on a specific resource.

```ts
owner: async (userId: string, resourceId: string) => {
  const project = await db.projects.findUnique({
    where: { id: resourceId },
  });
  return project?.ownerId === userId;
};
```

### 4. Graph Traversal

ReBAC treats resources as a **graph** where:

- **Nodes** = Resource instances (project-123, folder-456)
- **Edges** = Relationships (folder.projectId, file.folderId)
- **Traversal** = Checking permissions by following relationships

```
Project (owner)
  └─> Folder (inherits owner from project)
       └─> File (inherits owner from folder)
```

---

## Quick Start

### Step 1: Define Resources and Roles

Create `lib/auth/zanzibar.ts`:

```ts
import {
  createAccessControl,
  ZanzibarPlugin,
} from "better-auth-zanzibar-plugin";

// 1. Define resources and their actions
const resources = {
  project: ["create", "read", "update", "delete", "share"],
  folder: ["read", "update", "delete", "share"],
  file: ["read", "update", "delete"],
} as const;

const ac = createAccessControl(resources);

// 2. Define roles for each resource
const acRoles = ac.resourceRoles({
  project: [
    { name: "owner", actions: ["create", "read", "update", "delete", "share"] },
    { name: "editor", actions: ["read", "update"] },
    { name: "viewer", actions: ["read"] },
  ],
  folder: [
    { name: "owner", actions: ["read", "update", "delete", "share"] },
    { name: "viewer", actions: ["read"] },
  ],
  file: [
    { name: "owner", actions: ["read", "update", "delete"] },
    { name: "viewer", actions: ["read"] },
  ],
} as const);
```

### Step 2: Implement Role Conditions

```ts
// Your database helper functions
async function getProjectById(projectId: string) {
  return await db.projects.findUnique({ where: { id: projectId } });
}

async function getFolderById(folderId: string) {
  return await db.folders.findUnique({
    where: { id: folderId },
    include: { project: true },
  });
}

async function getFileById(fileId: string) {
  return await db.files.findUnique({
    where: { id: fileId },
    include: { folder: { include: { project: true } } },
  });
}

// 3. Define role conditions
const policies = acRoles.roleConditions({
  project: {
    owner: async (userId, resourceId) => {
      const project = await getProjectById(resourceId);
      return project?.ownerId === userId;
    },
    editor: async (userId, resourceId) => {
      const member = await db.projectMembers.findFirst({
        where: { userId, projectId: resourceId, role: "editor" },
      });
      return !!member;
    },
    viewer: async (userId, resourceId) => {
      const project = await getProjectById(resourceId);
      return (
        project?.isPublic ||
        (await acRoles.hasRole("project", "editor", userId, resourceId))
      );
    },
  },
  folder: {
    owner: async (userId, resourceId) => {
      const folder = await getFolderById(resourceId);
      // Folder owner = Project owner
      return folder?.projectId
        ? await acRoles.hasRole("project", "owner", userId, folder.projectId)
        : false;
    },
    viewer: async (userId, resourceId) => {
      const folder = await getFolderById(resourceId);
      // Can view folder if can view project
      return folder?.projectId
        ? await acRoles.hasRole("project", "viewer", userId, folder.projectId)
        : false;
    },
  },
  file: {
    owner: async (userId, resourceId) => {
      const file = await getFileById(resourceId);
      // File owner = Folder owner
      return file?.folderId
        ? await acRoles.hasRole("folder", "owner", userId, file.folderId)
        : false;
    },
    viewer: async (userId, resourceId) => {
      const file = await getFileById(resourceId);
      // Can view file if can view folder
      return file?.folderId
        ? await acRoles.hasRole("folder", "viewer", userId, file.folderId)
        : false;
    },
  },
} as const);

// 4. Export the plugin
export const zanzibar = ZanzibarPlugin(policies);
// Enable caching: export const zanzibar = ZanzibarPlugin(policies, true);
```

### Step 3: Add to Better Auth

In `lib/auth/auth.ts`:

```ts
import { betterAuth } from "better-auth";
import { zanzibar } from "./zanzibar";

export const auth = betterAuth({
  database: {
    // Your database configuration
  },
  plugins: [
    zanzibar,
    // ... other plugins
  ],
});
```

### Step 4: Setup Client (Optional)

```ts
import { createAuthClient } from "better-auth/client";
import { ZanzibarClientPlugin } from "better-auth-zanzibar-plugin";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [ZanzibarClientPlugin()],
});
```

---

## Configuration

### Plugin Options

```ts
ZanzibarPlugin(
  policies, // Required: Authorization policies
  cachingEnabled // Optional: Enable caching (default: false)
);
```

### Caching

When enabled, authorization results are cached for **5 minutes** (300 seconds).

**Cache Keys Include:**

- Resource type
- Role name or action
- User ID
- Resource ID (or `*` when `resourceId` is omitted for a global check)

```ts
// Development (no caching)
export const zanzibar = ZanzibarPlugin(policies, false);

// Production (with caching)
export const zanzibar = ZanzibarPlugin(policies, true);
```

**Performance Impact:**

- ✅ Faster repeated checks
- ✅ Reduced database load
- ⚠️ May show stale data for up to 5 minutes

---

## Usage Patterns

### Client-Side Usage

#### Check Single Role

```ts
// Check single role (userId inferred from session)
const isOwner = await authClient.zanzibar.hasRole(
  "project", // resource type
  "owner", // role name
  "project-123" // resource ID
);
// Returns: boolean

// Check single permission (userId inferred from session)
const canDelete = await authClient.zanzibar.hasPermission(
  "delete", // action
  "project", // resource type
  "project-123" // resource ID
);
// Returns: boolean

// Check multiple permissions
const namedPerms = await authClient.zanzibar.hasPermissions({
  project: {
    resourceType: "project",
    actions: ["create", "update", "delete"],
    resourceId: "project-123",
  },
  folderRead: {
    resourceType: "folder",
    action: "read",
    resourceId: "folder-456",
  },
});
// Returns: {
//   project: { allowed: boolean, message: string, results: { [action]: boolean } },
//   folderRead: { allowed: boolean, message: string }
// }
```

#### Global (resource-less) conditions

You can define role conditions that only depend on `userId` and call the checks without a `resourceId`. When `resourceId` is omitted, cache keys use `*` as the placeholder.

```ts
// Global condition example (role condition without resourceId)
const policies = acRoles.roleConditions({
  user: {
    siteAdmin: async (userId) => isSiteAdmin(userId),
  },
});

// Calls without resourceId (userId inferred from session)
await authClient.zanzibar.hasRole("user", "siteAdmin");
await authClient.zanzibar.hasPermission("manage", "user");
```

### Server-Side Usage

```ts
import { auth } from "./auth";
import { headers } from "next/headers";

// Check single role
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

// Check single permission
const permResult = await auth.api.hasPermission({
  headers: await headers(),
  body: {
    action: "delete",
    resourceType: "project",
    resourceId: "project-123",
  },
});

console.log(permResult.allowed); // boolean
console.log(permResult.message); // descriptive message

// Multiple permission checks
const namedResult = await auth.api.hasPermissions({
  headers: await headers(),
  body: {
    checks: {
      projectPerms: {
        resourceType: "project",
        actions: ["create", "update"],
        resourceId: "project-123",
      },
      folderPerms: {
        resourceType: "folder",
        action: "read",
        resourceId: "folder-456",
      },
    },
  },
});
```

> **Notes:**
>
> - The Better Auth API automatically extracts `userId` from the session via headers.
> - For global checks (no specific resource), server endpoints currently require a `resourceId` string. Use `"*"` as the placeholder to indicate a global check.

---

## API Reference

### Core Functions

| Function                                                   | Description                                  | Returns                                |
| ---------------------------------------------------------- | -------------------------------------------- | -------------------------------------- |
| `hasRole(resourceType, roleName, userId, resourceId?)`     | Check if user has a specific role            | `Promise<boolean>`                     |
| `hasPermission(userId, action, resourceType, resourceId?)` | Check if user has a specific permission      | `Promise<boolean>`                     |
| `hasPermissions(userId, checks)`                           | Check multiple permissions with custom names | `Promise<Record<string, CheckResult>>` |

### Server Endpoints

| Endpoint                    | Method | Description                |
| --------------------------- | ------ | -------------------------- |
| `/zanzibar/has-role`        | POST   | Check single role          |
| `/zanzibar/has-permission`  | POST   | Check single permission    |
| `/zanzibar/has-permissions` | POST   | Check multiple permissions |

---

## License

MIT
