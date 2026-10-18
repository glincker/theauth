/**
 * Resolves the signed-in user of a request for the headless module handlers
 * (`theauth.totp.handleRequest`, `theauth.passkey.handleRequest` and similar).
 *
 * Those handlers act on the user this returns, never on a `userId` taken from the request
 * body or query. With no resolver configured, or no signed-in user, they answer 401.
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import { extractToken } from "../plugin/helpers.js";
import type { SessionManager } from "../session/session.js";
import type { AuthAdapter } from "./types.js";

export type RequestUserResolver = (request: Request) => Promise<{ id: string } | null>;

/** Optional collaborators of a headless module's `handleRequest`. */
export interface ModuleRequestDeps {
	/** Finds the signed-in user. `createTheAuth` wires the auth adapter and the session manager. */
	resolveUser?: RequestUserResolver;
}

/** Auth adapter first, then the session token (Bearer header or session cookie). */
export function createRequestUserResolver(
	db: Database,
	sessionManager: SessionManager | null,
	adapter: AuthAdapter | null | undefined,
): RequestUserResolver {
	return async (request) => {
		if (adapter) {
			try {
				const user = await adapter.resolveUser(request);
				if (user) return { id: user.id };
			} catch {
				// An adapter error is "not signed in", never a pass.
			}
		}
		if (!sessionManager) return null;
		const token = extractToken(request);
		if (!token) return null;
		try {
			const session = await sessionManager.validate(token);
			if (!session) return null;
			const rows = await db
				.select({ id: users.id })
				.from(users)
				.where(eq(users.id, session.userId));
			return rows[0] ? { id: rows[0].id } : null;
		} catch {
			return null;
		}
	};
}

/** The signed-in user id, or null when there is no resolver or no user. Errors count as null. */
export async function requestUserId(
	request: Request,
	resolveUser: RequestUserResolver | undefined,
): Promise<string | null> {
	if (!resolveUser) return null;
	try {
		return (await resolveUser(request))?.id ?? null;
	} catch {
		return null;
	}
}

export function authenticationRequired(): Response {
	return new Response(JSON.stringify({ error: "Authentication required" }), {
		status: 401,
		headers: { "Content-Type": "application/json" },
	});
}
