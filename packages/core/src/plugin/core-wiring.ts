import { eq } from "drizzle-orm";
import { signInGatePlugin } from "../auth/sign-in-gate-plugin.js";
import type { ResolvedUser } from "../auth/types.js";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";
import type { TheAuthConfig } from "../types.js";
import { buildClearCookie, extractToken, json } from "./helpers.js";
import type { createPluginRouter } from "./router.js";
import type { PluginRegistry } from "./runner.js";
import type { EndpointContext, TheAuthPlugin } from "./types.js";

/** Append the sign-in gate routes unless the caller already registered them. */
export function withSignInGatePlugin(
	plugins: TheAuthPlugin[],
	hasSession: boolean,
): TheAuthPlugin[] {
	if (!hasSession || plugins.some((p) => p.id === "theauth-sign-in-gate")) return plugins;
	return [...plugins, signInGatePlugin()];
}

/** Resolves the request user (auth adapter first, then session token) for plugin endpoints. */
export function createEndpointContext(
	db: Database,
	config: TheAuthConfig,
	sessionManager: SessionManager | null,
): EndpointContext {
	const authAdapter = config.auth?.adapter ?? null;
	return {
		db,
		trustedProxy: config.trustedProxy,
		async getUser(request: Request): Promise<ResolvedUser | null> {
			if (authAdapter) {
				const user = await authAdapter.resolveUser(request);
				if (user) return user;
			}

			if (sessionManager) {
				const token = extractToken(request, sessionManager.cookieName);
				if (!token) return null;

				try {
					const session = await sessionManager.validate(token);
					if (!session) return null;

					const userRows = await db.select().from(users).where(eq(users.id, session.userId));
					const user = userRows[0];
					if (!user) return null;

					return {
						id: user.id,
						email: user.email ?? undefined,
						name: user.name ?? undefined,
					};
				} catch {
					return null;
				}
			}

			return null;
		},
		async getSession(token: string) {
			if (!sessionManager) return null;
			return sessionManager.validate(token);
		},
	};
}

/** Runs plugin `onRequest` hooks in order. A hook may short-circuit with a Response or swap the Request. */
export function createRequestHookRunner(
	registry: Pick<PluginRegistry, "hooks">,
): (request: Request) => Promise<Request | Response> {
	return async function runRequestHooks(request: Request): Promise<Request | Response> {
		let current = request;
		for (const hook of registry.hooks.onRequest) {
			if (!hook) continue;
			const result = await hook(current);
			if (result instanceof Response) return result;
			if (result instanceof Request) current = result;
		}
		return current;
	};
}

/** Registers `/auth/sign-out` and `/auth/session` on the plugin endpoint list. */
export function registerSessionEndpoints(
	registry: Pick<PluginRegistry, "endpoints">,
	sessionManager: SessionManager,
	endpointCtx: EndpointContext,
): void {
	registry.endpoints.push({
		method: "POST",
		path: "/auth/sign-out",
		metadata: { description: "Revoke the current session and clear cookie" },
		async handler(request) {
			const token = extractToken(request, sessionManager.cookieName);
			if (!token) return json({ error: "No session" }, 401);

			try {
				const session = await sessionManager.validate(token);
				if (session) {
					await sessionManager.revoke(session.id);
				}
			} catch {
				// Invalid token: still clear the cookie.
			}

			return new Response(JSON.stringify({ success: true }), {
				status: 200,
				headers: {
					"Content-Type": "application/json",
					"Set-Cookie": buildClearCookie(sessionManager.cookieName ?? "theauth_session"),
				},
			});
		},
	});

	registry.endpoints.push({
		method: "GET",
		path: "/auth/session",
		metadata: { description: "Get current session and user info" },
		async handler(request) {
			const user = await endpointCtx.getUser(request);
			if (!user) return json({ error: "Not authenticated" }, 401);

			const token = extractToken(request, sessionManager.cookieName);
			const session = token ? await sessionManager.validate(token) : null;

			return json({
				user,
				session: session ? { id: session.id, expiresAt: session.expiresAt } : null,
			});
		},
	});
}

/** The `theauth.plugins` facade: request routing, hooks and read access to plugin context. */
export function createPluginsFacade(deps: {
	pluginRegistry: PluginRegistry;
	pluginRouter: ReturnType<typeof createPluginRouter>;
	runRequestHooks: ReturnType<typeof createRequestHookRunner>;
	endpointCtx: EndpointContext;
}) {
	const { pluginRegistry, pluginRouter, runRequestHooks, endpointCtx } = deps;
	return {
		/** Route a request through plugin endpoints. Returns null if no plugin handles it. */
		async handleRequest(request: Request, basePath = ""): Promise<Response | null> {
			const hooked = await runRequestHooks(request);
			if (hooked instanceof Response) return hooked;
			return pluginRouter.handle(hooked, basePath, endpointCtx);
		},
		/** Runs plugin `onRequest` hooks for requests TheAuth does not route itself, such as `/mcp/token`. */
		runRequestHooks,
		getEndpoints() {
			return pluginRouter.getEndpoints();
		},
		getContext(): Record<string, unknown> {
			return { ...pluginRegistry.pluginContext };
		},
		registry: pluginRegistry,
	};
}
