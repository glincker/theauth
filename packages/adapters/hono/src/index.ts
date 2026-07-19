/**
 * theAuthHono mounts all TheAuth REST API routes on a Hono app.
 * createHonoAdapter is an alias, preferred when using the adapter as a
 * handler rather than mounting routes directly.
 *
 * @example Cloudflare Workers with D1
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { createHonoAdapter } from '@glinr/theauth-hono';
 * import { Hono } from 'hono';
 *
 * type Env = { Bindings: { DB: D1Database; SESSION_SECRET: string } };
 *
 * const app = new Hono<Env>();
 *
 * app.all('/auth/*', async (c) => {
 *   const kavach = await createTheAuth({
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
export { authHono, kavachHono, theAuthHono, theAuthHono as createHonoAdapter } from "./adapter.js";
