import type { ZodIssue } from "zod";
import type { ScopeDenial } from "../adapter-scope.js";

const JSON_HEADERS = { "Content-Type": "application/json" };

export function ok<T>(data: T, status = 200): Response {
	return new Response(JSON.stringify({ data }), { status, headers: JSON_HEADERS });
}

export function created<T>(data: T): Response {
	return ok(data, 201);
}

export function noContent(): Response {
	return new Response(null, { status: 204 });
}

export function errorResponse(
	code: string,
	message: string,
	status: number,
	headers?: HeadersInit,
): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { ...JSON_HEADERS, ...headers },
	});
}

export const badRequest = (message: string): Response => errorResponse("BAD_REQUEST", message, 400);
export const notFound = (message = "Not found"): Response =>
	errorResponse("NOT_FOUND", message, 404);
export const methodNotAllowed = (allow: string[]): Response =>
	errorResponse("METHOD_NOT_ALLOWED", "Method not allowed", 405, { Allow: allow.join(", ") });
export const internalError = (message = "Internal server error"): Response =>
	errorResponse("INTERNAL_ERROR", message, 500);
export const unauthorized = (message = "Unauthorized"): Response =>
	errorResponse("UNAUTHORIZED", message, 401, { "WWW-Authenticate": "Bearer" });

export function scopeDenied(denial: ScopeDenial): Response {
	return errorResponse(denial.code, denial.message, denial.status);
}

/** A management route reached without a resolved scope is refused (fail closed). */
export function scopeUnavailable(): Response {
	return errorResponse("FORBIDDEN", "Caller scope is unavailable", 403);
}

export function validationError(issues: ZodIssue[]): Response {
	const message = issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ");
	return badRequest(`Validation failed: ${message}`);
}

/** Structural check so this module needs no runtime import of the delegation errors. */
export function delegationErrorCode(err: unknown): string | null {
	if (err instanceof Error && err.name === "DelegationError") {
		const code = (err as Error & { code?: unknown }).code;
		if (typeof code === "string") return code;
	}
	return null;
}

/** Map a thrown error to a response. "not found" messages become 404, anything else 500 with a fixed message (internals are not echoed). */
export function failure(err: unknown, fallback: string): Response {
	const message = err instanceof Error ? err.message : "";
	if (message.includes("not found")) return notFound(message);
	return internalError(fallback);
}

type BodyResult = { ok: true; data: unknown } | { ok: false; response: Response };

/** Read a JSON body, refusing anything over `maxBytes`. */
export async function readJsonBody(request: Request, maxBytes: number): Promise<BodyResult> {
	const declared = Number(request.headers.get("content-length"));
	const tooLarge = (): BodyResult => ({
		ok: false,
		response: errorResponse("PAYLOAD_TOO_LARGE", "Request body is too large", 413),
	});
	if (Number.isFinite(declared) && declared > maxBytes) return tooLarge();
	try {
		const text = await request.text();
		if (new TextEncoder().encode(text).length > maxBytes) return tooLarge();
		return { ok: true, data: JSON.parse(text) as unknown };
	} catch {
		return { ok: false, response: badRequest("Invalid JSON body") };
	}
}

export function mcpOk<T>(data: T, status = 200, extra?: HeadersInit): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { ...JSON_HEADERS, ...extra },
	});
}

export function mcpError(code: string, message: string, status: number): Response {
	return mcpOk({ error: code, error_description: message }, status);
}

export function mcpNoStore<T>(data: T, status = 200): Response {
	return mcpOk(data, status, { "Cache-Control": "no-store", Pragma: "no-cache" });
}

/** Cache headers every response gets unless the route set its own (the discovery keys set `public`). */
const NO_STORE_DEFAULTS = { "Cache-Control": "no-store", Pragma: "no-cache" };

export interface FinalizeOptions {
	/** Set only when the response does not already carry the header (security headers). */
	defaults?: Record<string, string>;
	/** Set unconditionally (CORS decisions made by the router). */
	overrides?: Record<string, string>;
	/** Tokens appended to `Vary`. */
	vary?: string[];
}

function mutable(res: Response): Response {
	// Response.redirect() and fetch() results have immutable headers: rebuild those.
	try {
		res.headers.set("X-Theauth-Probe", "1");
		res.headers.delete("X-Theauth-Probe");
		return res;
	} catch {
		return new Response(res.body, {
			status: res.status,
			statusText: res.statusText,
			headers: new Headers(res.headers),
		});
	}
}

/**
 * The one place response headers are decided after a handler ran: `Cache-Control: no-store` and
 * `Pragma: no-cache` by default (a handler's own value wins), then the optional security headers
 * and CORS headers. Every auth response carries credentials or session state, so no-store is the rule.
 */
export function finalizeResponse(res: Response, options: FinalizeOptions = {}): Response {
	const out = mutable(res);
	const h = out.headers;
	for (const [name, value] of Object.entries(NO_STORE_DEFAULTS)) {
		if (!h.has(name)) h.set(name, value);
	}
	for (const [name, value] of Object.entries(options.defaults ?? {})) {
		if (!h.has(name)) h.set(name, value);
	}
	for (const [name, value] of Object.entries(options.overrides ?? {})) h.set(name, value);
	if (options.vary && options.vary.length > 0) {
		const existing = (h.get("Vary") ?? "")
			.split(",")
			.map((t) => t.trim())
			.filter(Boolean);
		const have = new Set(existing.map((t) => t.toLowerCase()));
		for (const token of options.vary) if (!have.has(token.toLowerCase())) existing.push(token);
		h.set("Vary", existing.join(", "));
	}
	return out;
}
