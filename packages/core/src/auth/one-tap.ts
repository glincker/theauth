/**
 * Google One Tap authentication for TheAuth.
 *
 * Verifies a Google ID token (issued by the Google Identity Services JS
 * library) server-side via Google's public JWKS endpoint. No Google SDK
 * required. Uses `jose` for JWT verification — the same library used
 * elsewhere in TheAuth.
 *
 * Flow:
 * 1. Front-end includes the Google Identity Services script and mounts the
 *    One Tap prompt.
 * 2. On sign-in the browser POSTs the `credential` (ID token) to
 *    POST /auth/one-tap/callback.
 * 3. This module verifies the token, finds or creates the user, and returns
 *    a session.
 *
 * CSRF: Google's JS library sets a `g_csrf_token` cookie and includes the
 * same value in the POST body. Both must match.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 * });
 *
 * // Use via plugin
 * import { oneTap } from 'theauth/auth';
 * // plugins: [oneTap({ clientId: process.env.GOOGLE_CLIENT_ID })]
 *
 * // Or use the module directly
 * const tap = createOneTapModule({ clientId: '...' }, db, sessionManager);
 * const googleUser = await tap.verify(idToken);
 * ```
 */

import { eq } from "drizzle-orm";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"] as const;
const DEFAULT_CSRF_COOKIE_NAME = "g_csrf_token";

// Lazily created — jose caches JWKS internally after first fetch.
let cachedJwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks(): ReturnType<typeof createRemoteJWKSet> {
	if (!cachedJwks) {
		cachedJwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
	}
	return cachedJwks;
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface OneTapConfig {
	/** Google OAuth client ID */
	clientId: string;
	/** Auto-create user if not found (default: true) */
	autoCreateUser?: boolean;
	/** CSRF token cookie name (default: "g_csrf_token") */
	csrfCookieName?: string;
}

export interface GoogleUser {
	/** Google user ID (stable, use this as the external ID) */
	sub: string;
	email: string;
	emailVerified: boolean;
	name: string;
	givenName?: string;
	familyName?: string;
	picture?: string;
}

export interface OneTapModule {
	/**
	 * Verify a Google ID token and return the decoded user claims.
	 * Throws if the token is invalid, expired, or issued for the wrong audience.
	 */
	verify(idToken: string): Promise<GoogleUser>;
	/**
	 * Handle the POST callback from Google's JS library.
	 *
	 * Expects `application/x-www-form-urlencoded` with `credential` and
	 * `g_csrf_token` fields (plus the matching CSRF cookie). Returns a JSON
	 * response with `{ user, session }` on success or null when the path does
	 * not match (allowing fall-through to other handlers).
	 */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class OneTapVerifyError extends Error {
	constructor(
		message: string,
		public readonly code: string,
	) {
		super(message);
		this.name = "OneTapVerifyError";
	}
}

// ---------------------------------------------------------------------------
// Google JWT payload shape
// ---------------------------------------------------------------------------

interface GoogleIdTokenPayload {
	sub: string;
	email: string;
	email_verified?: boolean;
	name?: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	iss: string;
	aud: string;
	exp: number;
	iat: number;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createOneTapModule(
	config: OneTapConfig,
	db: Database,
	sessionManager: SessionManager,
): OneTapModule {
	const autoCreateUser = config.autoCreateUser ?? true;
	const csrfCookieName = config.csrfCookieName ?? DEFAULT_CSRF_COOKIE_NAME;
	const callbackPath = "/auth/one-tap/callback";

	// ── verify ────────────────────────────────────────────────────────────

	async function verify(idToken: string): Promise<GoogleUser> {
		let payload: GoogleIdTokenPayload;

		try {
			const jwks = getJwks();
			const { payload: raw } = await jwtVerify(idToken, jwks, {
				issuer: [...GOOGLE_ISSUERS],
				audience: config.clientId,
			});
			payload = raw as unknown as GoogleIdTokenPayload;
		} catch (err) {
			const message = err instanceof Error ? err.message : "JWT verification failed";
			throw new OneTapVerifyError(
				`Google ID token verification failed: ${message}`,
				"INVALID_TOKEN",
			);
		}

		if (!payload.email) {
			throw new OneTapVerifyError("Google ID token is missing email claim", "MISSING_EMAIL");
		}

		if (!payload.sub) {
			throw new OneTapVerifyError("Google ID token is missing sub claim", "MISSING_SUB");
		}

		return {
			sub: payload.sub,
			email: payload.email,
			emailVerified: payload.email_verified === true,
			name: payload.name ?? payload.email,
			givenName: payload.given_name,
			familyName: payload.family_name,
			picture: payload.picture,
		};
	}

	// ── findOrCreate user ─────────────────────────────────────────────────

	async function findOrCreateUser(googleUser: GoogleUser): Promise<{ id: string; email: string }> {
		// Look up by email first.
		const existing = await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(eq(users.email, googleUser.email));

		if (existing[0]) {
			return { id: existing[0].id, email: existing[0].email };
		}

		if (!autoCreateUser) {
			throw new OneTapVerifyError(`No account found for ${googleUser.email}`, "USER_NOT_FOUND");
		}

		const id = generateId();
		const now = new Date();

		await db.insert(users).values({
			id,
			email: googleUser.email,
			name: googleUser.name,
			externalId: googleUser.sub,
			externalProvider: "google",
			createdAt: now,
			updatedAt: now,
		});

		return { id, email: googleUser.email };
	}

	// ── CSRF helpers ──────────────────────────────────────────────────────

	function getCsrfCookie(request: Request): string | null {
		const cookieHeader = request.headers.get("cookie") ?? "";
		for (const part of cookieHeader.split(";")) {
			const trimmed = part.trim();
			const eqIdx = trimmed.indexOf("=");
			if (eqIdx === -1) continue;
			const name = trimmed.slice(0, eqIdx).trim();
			if (name === csrfCookieName) {
				return trimmed.slice(eqIdx + 1).trim();
			}
		}
		return null;
	}

	// ── handleRequest ─────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);

		if (request.method !== "POST" || url.pathname !== callbackPath) {
			return null;
		}

		// Parse form body (Google JS library sends application/x-www-form-urlencoded).
		let formData: URLSearchParams;
		try {
			const text = await request.text();
			formData = new URLSearchParams(text);
		} catch {
			return jsonResponse({ error: "Failed to parse request body" }, 400);
		}

		const credential = formData.get("credential");
		const bodyToken = formData.get(csrfCookieName);

		if (!credential) {
			return jsonResponse({ error: "Missing credential field" }, 400);
		}

		// CSRF check: cookie and body field must both exist and match.
		const cookieToken = getCsrfCookie(request);
		if (!cookieToken || !bodyToken || cookieToken !== bodyToken) {
			return jsonResponse({ error: "CSRF token mismatch" }, 403);
		}

		let googleUser: GoogleUser;
		try {
			googleUser = await verify(credential);
		} catch (err) {
			if (err instanceof OneTapVerifyError && err.code === "USER_NOT_FOUND") {
				return jsonResponse({ error: err.message }, 403);
			}
			return jsonResponse(
				{ error: err instanceof Error ? err.message : "Token verification failed" },
				401,
			);
		}

		let user: { id: string; email: string };
		try {
			user = await findOrCreateUser(googleUser);
		} catch (err) {
			if (err instanceof OneTapVerifyError && err.code === "USER_NOT_FOUND") {
				return jsonResponse({ error: err.message }, 403);
			}
			return jsonResponse(
				{ error: err instanceof Error ? err.message : "Failed to resolve user" },
				500,
			);
		}

		const { token: sessionToken, session } = await sessionManager.create(user.id);

		return jsonResponse({
			user: { id: user.id, email: user.email },
			session: { token: sessionToken, expiresAt: session.expiresAt },
		});
	}

	return { verify, handleRequest };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}
