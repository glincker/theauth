import type { HttpRoute } from "./types.js";

/** Route groups CORS can be switched on for. `authorize` is a browser navigation and never gets CORS. */
export type CorsGroup = "discovery" | "register" | "token" | "introspect" | "revoke" | "management";

export interface CorsOptions {
	/** Exact origins allowed, such as `https://app.example.com` (no path, no trailing slash). `"*"` is allowed only for public documents and never with `credentials`. */
	origins: string[];
	/** Send `Access-Control-Allow-Credentials: true`. Refused at construction together with `"*"`. Default false. */
	credentials?: boolean;
	/**
	 * Per group: `true` uses `origins`, an array is that group's own allowlist, `false` is off.
	 * Defaults: `discovery` (the two `.well-known` documents and `/mcp/jwks`) on, everything else off.
	 * `token`, `introspect` and `revoke` carry credentials and stay off until you list them here.
	 */
	groups?: Partial<Record<CorsGroup, boolean | string[]>>;
	/** Request headers a preflight may use. Default `Content-Type, Authorization, DPoP`. */
	allowedHeaders?: string[];
	/** Response headers scripts may read. Default `DPoP-Nonce, WWW-Authenticate`. */
	exposedHeaders?: string[];
	/** Preflight cache seconds. Default 600. */
	maxAge?: number;
}

const DEFAULT_ALLOWED_HEADERS = ["Content-Type", "Authorization", "DPoP"];
const DEFAULT_EXPOSED_HEADERS = ["DPoP-Nonce", "WWW-Authenticate"];
const DEFAULT_MAX_AGE = 600;
const GROUPS: CorsGroup[] = [
	"discovery",
	"register",
	"token",
	"introspect",
	"revoke",
	"management",
];
const SENSITIVE: CorsGroup[] = ["token", "introspect", "revoke", "management"];

/** Which CORS group a route belongs to, or null when it never gets CORS. */
export function corsGroupOf(route: Pick<HttpRoute, "path" | "group">): CorsGroup | null {
	const p = route.path;
	if (p.startsWith("/.well-known/") || p === "/mcp/jwks") return "discovery";
	if (p === "/mcp/register") return "register";
	if (p === "/mcp/token") return "token";
	if (p === "/mcp/introspect") return "introspect";
	if (p === "/mcp/revoke") return "revoke";
	if (route.group === "management" || route.group === "explain") return "management";
	return null;
}

function normalizeOrigin(entry: string): string {
	if (entry === "*") return entry;
	let origin: string;
	try {
		origin = new URL(entry).origin;
	} catch {
		throw new Error(`[theauth] cors.origins: "${entry}" is not an origin`);
	}
	if (origin === "null" || origin !== entry.toLowerCase()) {
		throw new Error(
			`[theauth] cors.origins: "${entry}" must be an exact origin like ${origin} (scheme, host, optional port, nothing else)`,
		);
	}
	return origin;
}

export interface CorsDecision {
	/** Headers to set on the response (empty when CORS is off or the origin is not allowed). */
	headers: Record<string, string>;
	/** Tokens to add to `Vary`. */
	vary: string[];
	/** True when the group has CORS configured at all. */
	enabled: boolean;
}

export interface Cors {
	/** Headers for a normal response of `route`. */
	forResponse(request: Request, route: Pick<HttpRoute, "path" | "group">): CorsDecision;
	/** Headers for a preflight; `methods` are the methods the path serves. Empty headers means refuse. */
	forPreflight(
		request: Request,
		route: Pick<HttpRoute, "path" | "group">,
		methods: string[],
	): CorsDecision;
	/** Human readable descriptions of risky choices, for the startup warning. */
	warnings(): string[];
}

/** Resolve and validate CORS options. Throws on a wildcard combined with credentials. */
export function createCors(options: CorsOptions): Cors {
	const base = options.origins.map(normalizeOrigin);
	const credentials = options.credentials === true;
	const lists = new Map<CorsGroup, string[]>();
	for (const group of GROUPS) {
		const setting = options.groups?.[group] ?? group === "discovery";
		if (setting === false) continue;
		const list = setting === true ? base : setting.map(normalizeOrigin);
		if (list.length === 0) continue;
		if (credentials && list.includes("*")) {
			throw new Error(
				`[theauth] cors: "*" cannot be combined with credentials (group "${group}"). List exact origins instead.`,
			);
		}
		if (list.includes("*") && SENSITIVE.includes(group)) {
			throw new Error(
				`[theauth] cors: "*" is not allowed for the "${group}" group. List exact origins instead.`,
			);
		}
		lists.set(group, list);
	}
	const allowedHeaders = (options.allowedHeaders ?? DEFAULT_ALLOWED_HEADERS).join(", ");
	const exposed = (options.exposedHeaders ?? DEFAULT_EXPOSED_HEADERS).join(", ");
	const maxAge = String(options.maxAge ?? DEFAULT_MAX_AGE);

	function decide(
		request: Request,
		route: Pick<HttpRoute, "path" | "group">,
		extra: (headers: Record<string, string>) => void,
		preflight: boolean,
	): CorsDecision {
		const group = corsGroupOf(route);
		const list = group ? lists.get(group) : undefined;
		if (!list) return { headers: {}, vary: [], enabled: false };
		const wildcard = list.includes("*");
		const vary = wildcard ? [] : ["Origin"];
		if (preflight) vary.push("Access-Control-Request-Method", "Access-Control-Request-Headers");
		const origin = request.headers.get("origin");
		// Exact match only: an unlisted origin never gets Access-Control-Allow-Origin.
		const allowed = origin !== null && (wildcard || list.includes(origin));
		if (!allowed || origin === null) return { headers: {}, vary, enabled: true };
		const headers: Record<string, string> = {
			"Access-Control-Allow-Origin": wildcard ? "*" : origin,
		};
		if (credentials) headers["Access-Control-Allow-Credentials"] = "true";
		extra(headers);
		return { headers, vary, enabled: true };
	}

	return {
		forResponse(request, route) {
			return decide(
				request,
				route,
				(h) => {
					h["Access-Control-Expose-Headers"] = exposed;
				},
				false,
			);
		},
		forPreflight(request, route, methods) {
			const requested = request.headers.get("access-control-request-method")?.toUpperCase();
			const decision = decide(
				request,
				route,
				(h) => {
					h["Access-Control-Allow-Methods"] = [...methods, "OPTIONS"].join(", ");
					h["Access-Control-Allow-Headers"] = allowedHeaders;
					h["Access-Control-Max-Age"] = maxAge;
				},
				true,
			);
			if (!requested || !methods.includes(requested)) return { ...decision, headers: {} };
			return decision;
		},
		warnings() {
			const out: string[] = [];
			for (const [group, list] of lists) {
				if (list.includes("*")) out.push(`cors: group "${group}" allows any origin ("*")`);
				if (SENSITIVE.includes(group)) {
					out.push(
						`cors: credential-bearing group "${group}" is reachable from ${list.join(", ")}`,
					);
				}
			}
			return out;
		},
	};
}
