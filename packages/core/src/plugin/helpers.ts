/**
 * Shared helpers for TheAuth plugin endpoints.
 *
 * Replaces the copy-pasted parseBody/jsonResponse helpers that were
 * duplicated across email-otp, passkey, stripe, admin, api-key, gdpr,
 * and polar plugins.
 */

/**
 * Create a JSON response with proper headers.
 */
export function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

/**
 * Parse JSON body from a request.
 * Returns a discriminated union so callers get clear error feedback
 * instead of a silent empty object.
 */
export async function parseBody(
	request: Request,
): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false; response: Response }> {
	try {
		const data = (await request.json()) as Record<string, unknown>;
		return { ok: true, data };
	} catch {
		return {
			ok: false,
			response: json({ error: "Invalid JSON body" }, 400),
		};
	}
}

/**
 * Extract a cookie value from a request.
 */
export function getCookie(request: Request, name: string): string | null {
	const header = request.headers.get("cookie");
	if (!header) return null;
	const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
	return match?.[1] ? decodeURIComponent(match[1]) : null;
}

/**
 * Build a Set-Cookie header value.
 */
export function buildSetCookie(
	name: string,
	value: string,
	maxAge: number,
	path = "/",
	secure = true,
): string {
	const parts = [
		`${name}=${encodeURIComponent(value)}`,
		"HttpOnly",
		"SameSite=Lax",
		`Path=${path}`,
		`Max-Age=${maxAge}`,
	];
	if (secure) parts.splice(1, 0, "Secure");
	return parts.join("; ");
}

/**
 * Build a Set-Cookie header that clears a cookie.
 */
export function buildClearCookie(name: string, path = "/"): string {
	return `${name}=; HttpOnly; Secure; SameSite=Lax; Path=${path}; Max-Age=0`;
}

/**
 * Extract a Bearer token from the Authorization header,
 * or fall back to a named cookie.
 */
export function extractToken(request: Request, cookieName = "theauth_session"): string | null {
	const authHeader = request.headers.get("authorization");
	if (authHeader?.startsWith("Bearer ")) {
		return authHeader.slice(7);
	}
	return getCookie(request, cookieName);
}
