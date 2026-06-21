/**
 * Alias for kavachHono — preferred name when using the adapter as a handler
 * rather than mounting routes directly.
 *
 * @example Cloudflare Workers with D1
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { createHonoAdapter } from '@glinr/theauth-hono';
 * import { Hono } from 'hono';
 *
 * type Env = { Bindings: { DB: D1Database; SESSION_SECRET: string } };
 *
 * const app = new Hono<Env>();
 *
 * app.all('/auth/*', async (c) => {
 *   const kavach = await createKavach({
 *     database: { provider: 'd1', binding: c.env.DB },
 *     auth: { session: { secret: c.env.SESSION_SECRET } },
 *   });
 *   const api = createHonoAdapter(kavach);
 *   return app.fetch(c.req.raw);
 * });
 *
 * export default app;
 * ```
 */
export { kavachHono, kavachHono as createHonoAdapter } from "./adapter.js";
