import { createHash, timingSafeEqual } from "node:crypto";

function digest(value: string): Buffer {
	return createHash("sha256").update(value).digest();
}

/**
 * Resolver for the management routes (/api/agents, /api/audit, ...).
 *
 * Callers must send `Authorization: Bearer <ADMIN_API_KEY>`. If ADMIN_API_KEY
 * is not set, every request is rejected. Swap this for a session or SSO
 * check before you expose the server beyond localhost.
 */
export async function authenticateAdmin(request: Request): Promise<{ id: string } | null> {
	const key = process.env["ADMIN_API_KEY"];
	if (!key) return null;
	const header = request.headers.get("authorization");
	if (!header?.startsWith("Bearer ")) return null;
	const supplied = digest(header.slice("Bearer ".length));
	return timingSafeEqual(supplied, digest(key)) ? { id: "admin" } : null;
}
