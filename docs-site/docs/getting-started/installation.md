---
title: Installation
description: Install TheAuth via pnpm, npm, yarn, or bun. Covers peer dependencies for each database provider.
---

# Installation

## Core package

=== "pnpm"
    ```bash
    pnpm add @glinr/theauth
    ```
=== "npm"
    ```bash
    npm install @glinr/theauth
    ```
=== "yarn"
    ```bash
    yarn add @glinr/theauth
    ```
=== "bun"
    ```bash
    bun add @glinr/theauth
    ```

## Scaffold a full app

The `create-theauth-app` scaffolder creates a running Next.js SaaS with TheAuth wired up:

=== "pnpm"
    ```bash
    pnpm create theauth-app my-app
    cd my-app && pnpm install && pnpm db:push && pnpm dev
    ```
=== "npm"
    ```bash
    npm create theauth-app my-app
    cd my-app && npm install && npm run db:push && npm run dev
    ```
=== "yarn"
    ```bash
    yarn create theauth-app my-app
    cd my-app && yarn install && yarn db:push && yarn dev
    ```
=== "bun"
    ```bash
    bun create theauth-app my-app
    cd my-app && bun install && bun db:push && bun dev
    ```

The CLI asks for a directory, a template, a package manager, and a database driver. Next steps are printed at the end.

## Framework adapters

Install the adapter for your framework alongside the core:

=== "Next.js"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-nextjs
    ```
=== "Hono"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-hono hono
    ```
=== "Express"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-express express
    ```
=== "Fastify"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-fastify fastify
    ```
=== "NestJS"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-nestjs @nestjs/core @nestjs/common
    ```
=== "SvelteKit"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-sveltekit
    ```
=== "Nuxt"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-nuxt
    ```
=== "Astro"
    ```bash
    pnpm add @glinr/theauth @glinr/theauth-astro
    ```

## Database peer dependencies

The core ships with `better-sqlite3` for SQLite. For other providers install the driver:

=== "Postgres"
    ```bash
    pnpm add pg
    pnpm add -D @types/pg
    ```
=== "MySQL"
    ```bash
    pnpm add mysql2
    ```
=== "Cloudflare D1"
    No extra dependency. Pass the `D1Database` binding from your Worker environment.

## Client SDKs

=== "React"
    ```bash
    pnpm add @glinr/theauth-react
    ```
=== "Vue"
    ```bash
    pnpm add @glinr/theauth-vue
    ```
=== "Svelte"
    ```bash
    pnpm add @glinr/theauth-svelte
    ```
=== "Expo / React Native"
    ```bash
    pnpm add @glinr/theauth-expo
    ```
=== "Electron"
    ```bash
    pnpm add @glinr/theauth-electron
    ```

## TypeScript

TheAuth ships types. No `@types/` package needed.

Minimum TypeScript version: **5.0**.

## Next steps

- [Quick Start](quick-start.md) - Create an agent and run your first authorization check.
- [Choosing an Adapter](choosing-an-adapter.md) - Pick the right framework adapter.
- [Configuration](../reference/configuration.md) - All `createKavach()` options.
