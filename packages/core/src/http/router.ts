import { createAdapterAdmission } from "../adapter-admit.js";
import { createAdapterGuard, isProtectedAdapterPath } from "../adapter-guard.js";
import type { McpMountedRoutes } from "../mcp/metadata.js";
import { ALL_MCP_ROUTES } from "../mcp/metadata.js";
import { NOOP_LOGGER } from "../observability/index.js";
import type { TheAuth } from "../theauth-core.js";
import { createCors } from "./cors.js";
import { resolveRequestIp } from "./node.js";
import { finalizeResponse, internalError, methodNotAllowed, notFound } from "./respond.js";
import { agentRoutes } from "./routes/agents.js";
import { auditRoutes } from "./routes/audit.js";
import { authorizeRoutes } from "./routes/authorize.js";
import { delegationRoutes } from "./routes/delegations.js";
import { explainRoutes } from "./routes/explain.js";
import { mcpRoutes } from "./routes/mcp.js";
import { isSecureRequest, securityHeaders } from "./security-headers.js";
import type {
	HttpRoute,
	RouteContext,
	RouteSpec,
	TheAuthHandler,
	TheAuthHandlerOptions,
} from "./types.js";

const ALL_ROUTES: HttpRoute[] = [
	...agentRoutes,
	...authorizeRoutes,
	...delegationRoutes,
	...auditRoutes,
	...mcpRoutes,
	...explainRoutes,
];

const DEFAULT_BASE_PATH = "/api/theauth";
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

/** The MCP endpoints mounted for these options (all of them unless `routes.mcp` narrows it). */
export function resolveMountedMcpRoutes(options?: TheAuthHandlerOptions): McpMountedRoutes {
	const setting = options?.routes?.mcp;
	if (setting === undefined || setting === true) return { ...ALL_MCP_ROUTES };
	if (setting === false) {
		return {
			register: false,
			authorize: false,
			token: false,
			revoke: false,
			introspect: false,
			jwks: false,
		};
	}
	return { ...ALL_MCP_ROUTES, ...setting };
}

function isServed(route: HttpRoute, options: TheAuthHandlerOptions | undefined): boolean {
	const routes = options?.routes;
	if (route.group === "management") return routes?.management !== false;
	if (route.group === "explain") return routes?.explain !== false;
	if (routes?.mcp === false) return false;
	const mounted = resolveMountedMcpRoutes(options);
	return route.mcpRoute === undefined || mounted[route.mcpRoute];
}

/** Every route this handler serves for `options`, in table order. Same input drives the docs and OpenAPI. */
export function listRoutes(options?: TheAuthHandlerOptions): RouteSpec[] {
	return ALL_ROUTES.filter((r) => isServed(r, options)).map(
		({ group: _group, mcpRoute: _mcpRoute, handle: _handle, ...spec }) => spec,
	);
}

interface CompiledRoute {
	route: HttpRoute;
	pattern: RegExp;
	names: string[];
}

function compile(route: HttpRoute): CompiledRoute {
	const names: string[] = [];
	const source = route.path
		.split("/")
		.map((segment) => {
			if (segment.startsWith(":")) {
				names.push(segment.slice(1));
				return "([^/]+)";
			}
			return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		})
		.join("/");
	return { route, pattern: new RegExp(`^${source}$`), names };
}

function decode(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

function relativePathOf(pathname: string, basePath: string): string | null {
	if (basePath === "") return pathname || "/";
	if (pathname === basePath) return "/";
	return pathname.startsWith(`${basePath}/`) ? pathname.slice(basePath.length) : null;
}

/** What the handler needs from the guard. Without management or explain routes there is nothing to authenticate, so only admission is built. */
interface Gate {
	admit: (request: Request, path: string) => Promise<Response | null>;
	clientIp: (request: Request) => string | null;
	resolve: ReturnType<typeof createAdapterGuard>["resolve"] | null;
}

function buildGate(auth: TheAuth, options: TheAuthHandlerOptions | undefined): Gate {
	const needsAuth = options?.routes?.management !== false || options?.routes?.explain !== false;
	if (needsAuth) {
		// Fails closed at construction when nothing can authenticate callers.
		const guard = createAdapterGuard(auth, options, "createTheAuthHandler");
		return { admit: guard.admit, clientIp: guard.clientIp, resolve: guard.resolve };
	}
	const admission = createAdapterAdmission(
		options,
		options?.trustedProxy,
		auth.secondaryStorage?.for("rateLimit"),
	);
	return {
		admit: (request, path) => admission.admit(request, path),
		clientIp: (request) => resolveRequestIp(request, options?.trustedProxy),
		resolve: null,
	};
}

/** Doctor-style startup warning for unsafe opt-outs, through the observability logger (console when none is set). */
function warnAboutRiskyOptions(
	auth: TheAuth,
	options: TheAuthHandlerOptions | undefined,
	corsWarnings: string[],
): void {
	const messages = [...corsWarnings];
	if (options?.allowUnauthenticated === true) {
		messages.unshift("allowUnauthenticated: management routes are open to anyone");
	}
	const logger = auth.observability.logger;
	for (const message of messages) {
		const text = `createTheAuthHandler: ${message}`;
		if (logger !== NOOP_LOGGER) logger.warn(text, { source: "http", check: "handler-options" });
		else if (!message.startsWith("allowUnauthenticated")) {
			// biome-ignore lint/suspicious/noConsole: startup warning when no logger is configured (the guard already warns for allowUnauthenticated)
			console.warn(`[theauth] ${text}`);
		}
	}
}

/** Linear-time trailing slash trim (a `/\/+$/` regex backtracks quadratically on long slash runs). */
function trimTrailingSlashes(value: string): string {
	let end = value.length;
	while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
	return value.slice(0, end);
}

/**
 * Build the single web-standard HTTP handler for TheAuth: `(Request) => Promise<Response>`.
 * Framework adapters only translate their request and response types around it.
 * Order per request: rate limit and cross-site check, authentication for admin routes, route handler, plugin routes, 404.
 */
export function createTheAuthHandler(
	auth: TheAuth,
	options?: TheAuthHandlerOptions,
): TheAuthHandler {
	const basePath = trimTrailingSlashes(options?.basePath ?? DEFAULT_BASE_PATH);
	const maxBodyBytes = options?.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
	const mounted = resolveMountedMcpRoutes(options);
	const gate = buildGate(auth, options);
	const served = ALL_ROUTES.filter((r) => isServed(r, options)).map(compile);

	const cors = options?.cors ? createCors(options.cors) : null;
	const hardening = options?.securityHeaders;
	const hardeningOptions = typeof hardening === "object" ? hardening : {};
	warnAboutRiskyOptions(auth, options, cors?.warnings() ?? []);

	/** Every response the handler produces passes through here (except a 404 for an unknown route). */
	const finish = (
		request: Request,
		response: Response,
		route: Pick<HttpRoute, "path" | "group"> | null,
	): Response => {
		const overrides: Record<string, string> = {};
		const vary: string[] = [];
		if (cors && route) {
			const decision = cors.forResponse(request, route);
			Object.assign(overrides, decision.headers);
			vary.push(...decision.vary);
		}
		let defaults: Record<string, string> | undefined;
		if (hardening) {
			const html = (response.headers.get("content-type") ?? "").toLowerCase().includes("text/html");
			defaults = securityHeaders({
				...hardeningOptions,
				secure: isSecureRequest(request, options?.trustedProxy),
				html,
			});
		}
		return finalizeResponse(response, { defaults, overrides, vary });
	};

	return async (request) => {
		const url = new URL(request.url);
		const path = relativePathOf(url.pathname, basePath);
		if (path === null) return notFound("Route not found");
		const method = request.method.toUpperCase();

		const refused = await gate.admit(request, path);
		if (refused) return finish(request, refused, null);

		const matches = served.filter((c) => c.pattern.test(path));
		const hit = matches.find((c) => c.route.method === method);
		const routeOf = (matches[0] ?? null)?.route ?? null;

		// Preflights carry no credentials, so they are answered before authentication.
		if (method === "OPTIONS" && routeOf) {
			const methods = [...new Set(matches.map((c) => c.route.method))];
			const headers: Record<string, string> = { Allow: [...methods, "OPTIONS"].join(", ") };
			const vary: string[] = [];
			if (cors && request.headers.has("origin")) {
				const decision = cors.forPreflight(request, routeOf, methods);
				Object.assign(headers, decision.headers);
				vary.push(...decision.vary);
			}
			return finalizeResponse(new Response(null, { status: 204, headers }), {
				defaults: hardening
					? securityHeaders({
							...hardeningOptions,
							secure: isSecureRequest(request, options?.trustedProxy),
						})
					: undefined,
				vary,
			});
		}

		// Management routes need an authenticated caller. The scope limits the default session
		// resolver to the caller's own resources; a custom resolver gets an unrestricted scope.
		let scope: RouteContext["scope"] = null;
		const protectedPath =
			hit?.route.auth === "admin" ||
			isProtectedAdapterPath(path) ||
			matches.some((c) => c.route.auth === "admin");
		if (protectedPath && gate.resolve) {
			const resolved = await gate.resolve(request);
			if (!resolved.ok) return finish(request, resolved.response, routeOf);
			scope = resolved.scope;
		}

		if (hit) {
			const values = hit.pattern.exec(path)?.slice(1) ?? [];
			const params: Record<string, string> = {};
			hit.names.forEach((name, i) => {
				params[name] = decode(values[i] ?? "");
			});
			try {
				const response = await hit.route.handle({
					auth,
					request,
					url,
					params,
					scope,
					clientIp: gate.clientIp,
					mcp: options?.mcp,
					mounted,
					maxBodyBytes,
				});
				return finish(request, response, hit.route);
			} catch {
				return finish(request, internalError(), hit.route);
			}
		}

		if (options?.routes?.plugins !== false) {
			const pluginResponse = await auth.plugins.handleRequest(request, basePath);
			if (pluginResponse !== null) return finish(request, pluginResponse, null);
		}
		if (matches.length > 0) {
			return finish(
				request,
				methodNotAllowed([...new Set(matches.map((c) => c.route.method))]),
				routeOf,
			);
		}
		return notFound("Route not found");
	};
}
