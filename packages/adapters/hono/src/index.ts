/**
 * Hono adapter for TheAuth: a thin wrapper around `createTheAuthHandler`.
 *
 * ```typescript
 * import { Hono } from "hono";
 * import { theAuthHono } from "@glinr/theauth-hono";
 *
 * const app = new Hono();
 * app.route("/api/theauth", theAuthHono(auth, { mcp }));
 * ```
 */

export type { TheAuthHonoOptions } from "./adapter.js";
export { theAuthHono, theAuthHono as createHonoAdapter } from "./adapter.js";
export type { AgentEnv, RequireScopeOptions } from "./require-scope.js";
export { requireScope } from "./require-scope.js";
