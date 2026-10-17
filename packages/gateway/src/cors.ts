import type { CorsConfig } from "./types.js";

const DEFAULT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
const DEFAULT_HEADERS = ["Content-Type", "Authorization"];
/** Headers the MCP streamable HTTP transport and DPoP need from browser clients. */
const MCP_HEADERS = ["Accept", "Mcp-Session-Id", "MCP-Protocol-Version", "Last-Event-ID", "DPoP"];
const MCP_EXPOSED = "WWW-Authenticate, Mcp-Session-Id, DPoP-Nonce";

/**
 * Build CORS headers from a CorsConfig.
 * Returns an empty object if no config is provided.
 */
export function buildCorsHeaders(
	cors: CorsConfig | undefined,
	requestOrigin: string | null,
	mcp = false,
): Record<string, string> {
	if (!cors) return {};

	const origins = cors.origins ?? "*";
	let allowOrigin: string | null;

	if (origins === "*") {
		allowOrigin = "*";
	} else if (Array.isArray(origins)) {
		// Echo only an origin that is on the list. Anything else gets no CORS grant.
		allowOrigin = requestOrigin && origins.includes(requestOrigin) ? requestOrigin : null;
	} else {
		allowOrigin = origins;
	}

	const methods = (cors.methods ?? DEFAULT_METHODS).join(", ");
	const headers = (
		cors.headers ?? (mcp ? [...DEFAULT_HEADERS, ...MCP_HEADERS] : DEFAULT_HEADERS)
	).join(", ");
	const maxAge = String(cors.maxAge ?? 86400);

	const result: Record<string, string> = {
		...(allowOrigin ? { "Access-Control-Allow-Origin": allowOrigin } : {}),
		...(Array.isArray(origins) ? { Vary: "Origin" } : {}),
		...(mcp ? { "Access-Control-Expose-Headers": MCP_EXPOSED } : {}),
		"Access-Control-Allow-Methods": methods,
		"Access-Control-Allow-Headers": headers,
		"Access-Control-Max-Age": maxAge,
	};

	if (cors.credentials) {
		result["Access-Control-Allow-Credentials"] = "true";
	}

	return result;
}

/**
 * Whether the request is a CORS preflight.
 */
export function isPreflight(request: Request): boolean {
	return request.method === "OPTIONS";
}

/**
 * Whether a request's Origin may reach the gateway. A request with no Origin
 * (a non-browser client) and a same-origin request pass. Otherwise the origin
 * must be listed in `cors`.
 */
export function isOriginAllowed(
	cors: CorsConfig | undefined,
	origin: string | null,
	host: string,
): boolean {
	if (!origin) return true;
	try {
		if (new URL(origin).host === host) return true;
	} catch {
		return false;
	}
	if (!cors) return false;
	const origins = cors.origins ?? "*";
	if (origins === "*") return true;
	return Array.isArray(origins) ? origins.includes(origin) : origins === origin;
}
