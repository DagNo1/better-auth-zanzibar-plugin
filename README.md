# Better Auth Zanzibar Plugin

A small, framework-agnostic Zanzibar-style authorization helper designed to plug into Better Auth. It includes:

- Server plugin (`ZanzibarPlugin`) exposing `/zanzibar/check` endpoint
- Client plugin (`ZanzibarClientPlugin`) for convenient checks from Better Auth client
- Type-safe policy builder (`createAccessControl`) and an in-memory `PolicyEngine`

## Install

```bash
npm install better-auth-zanzibar-plugin
```

## Quick start

```ts
import { createAccessControl } from "better-auth-zanzibar-plugin";
import { ZanzibarPlugin } from "better-auth-zanzibar-plugin";

// 1) Define resources and roles
const policies = createAccessControl({
  documents: ["read", "write", "delete"] as const,
})
  .resourceRoles({
    documents: [
      { name: "viewer", actions: ["read"] },
      { name: "editor", actions: ["read", "write"] },
      { name: "admin", actions: ["read", "write", "delete"] },
    ],
  })
  .roleConditions({
    documents: {
      viewer: async (userId, docId) => userId === "u1",
      editor: async (userId, docId) => userId === "u2",
      admin: async (userId, docId) => userId === "u3",
    },
  });

// 2) Create Better Auth plugin
export const zanzibar = ZanzibarPlugin(policies);
```

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

## License

MIT
