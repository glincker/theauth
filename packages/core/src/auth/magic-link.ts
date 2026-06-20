/**
 * Magic link authentication for TheAuth.
 *
 * Sends a one-time-use signed link to the user's email. When the link is
 * clicked the token is verified, the user is found or created, and a session
 * is returned. The transport (SMTP, Resend, SES, etc.) is provided by the
 * caller via `sendMagicLink`.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   magicLink: {
 *     appUrl: 'https://app.example.com',
 *     sendMagicLink: async (email, _token, url) => {
 *       await resend.emails.send({ to: email, subject: 'Sign in', html: `<a href="${url}">Sign in</a>` });
 *     },
 *   },
 * });
 *
 * // In your route handler
 * const response = await kavach.magicLink.handleRequest(request);
 * if (response) return response;
 * ```
 */

import { and, eq, gt } from "drizzle-orm";
import { generateId, randomBytesHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { magicLinks, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface MagicLinkConfig {
	/** Send the magic link email. You provide the transport. */
	sendMagicLink: (email: string, token: string, url: string) => Promise<void>;
	/** Base URL for magic link (e.g. "https://app.example.com") */
	appUrl: string;
	/** Token expiry in seconds (default: 900 = 15 minutes) */
	tokenExpiry?: number;
	/** Callback path (default: "/auth/magic-link/verify") */
	callbackPath?: string;
}

export interface MagicLinkModule {
	/** Send a magic link to the user's email. */
	sendLink: (email: string) => Promise<{ sent: boolean }>;
	/**
	 * Verify a magic link token and create a session.
	 * Returns null when the token is invalid, expired, or already used.
	 */
	verify: (token: string) => Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date };
	} | null>;
	/**
	 * Handle an incoming HTTP request.
	 *
	 * - `POST /auth/magic-link/send` – JSON body `{ email: string }`
	 * - `GET  /auth/magic-link/verify?token=<token>`
	 *
	 * Returns null when the path does not match (so callers can fall through
	 * to other handlers).
	 */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_EXPIRY_SECONDS = 900; // 15 minutes
const DEFAULT_CALLBACK_PATH = "/auth/magic-link/verify";

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createMagicLinkModule(
	config: MagicLinkConfig,
	db: Database,
	sessionManager: SessionManager,
): MagicLinkModule {
	const tokenExpiry = config.tokenExpiry ?? DEFAULT_EXPIRY_SECONDS;
	const callbackPath = config.callbackPath ?? DEFAULT_CALLBACK_PATH;

	// ── helpers ─────────────────────────────────────────────────────────────

	/** Find an existing user by email or create a new one. */
	async function findOrCreateUser(email: string): Promise<{ id: string; email: string }> {
		const existing = await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(eq(users.email, email));

		if (existing[0]) return { id: existing[0].id, email: existing[0].email };

		const id = generateId();
		const now = new Date();
		await db.insert(users).values({
			id,
			email,
			createdAt: now,
			updatedAt: now,
		});

		return { id, email };
	}

	// ── public API ───────────────────────────────────────────────────────────

	async function sendLink(email: string): Promise<{ sent: boolean }> {
		const token = randomBytesHex(32);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + tokenExpiry * 1000);

		// Ensure the user record exists before issuing a link.
		await findOrCreateUser(email);

		await db.insert(magicLinks).values({
			id: generateId(),
			email,
			token,
			expiresAt,
			used: false,
			createdAt: now,
		});

		const url = `${config.appUrl}${callbackPath}?token=${token}`;
		await config.sendMagicLink(email, token, url);

		return { sent: true };
	}

	async function verify(token: string): Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date };
	} | null> {
		const now = new Date();

		const rows = await db
			.select()
			.from(magicLinks)
			.where(
				and(eq(magicLinks.token, token), eq(magicLinks.used, false), gt(magicLinks.expiresAt, now)),
			);

		const link = rows[0];
		if (!link) return null;

		// Mark as used immediately to prevent replay.
		await db.update(magicLinks).set({ used: true }).where(eq(magicLinks.id, link.id));

		const user = await findOrCreateUser(link.email);
		const { token: sessionToken, session } = await sessionManager.create(user.id);

		return {
			user,
			session: { token: sessionToken, expiresAt: session.expiresAt },
		};
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		// POST /auth/magic-link/send
		if (request.method === "POST" && pathname === "/auth/magic-link/send") {
			let body: unknown;
			try {
				body = await request.json();
			} catch {
				return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			if (
				typeof body !== "object" ||
				body === null ||
				typeof (body as Record<string, unknown>).email !== "string"
			) {
				return new Response(JSON.stringify({ error: "Missing required field: email" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			const email = String((body as Record<string, unknown>).email)
				.trim()
				.toLowerCase();
			const result = await sendLink(email);
			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		// GET /auth/magic-link/verify?token=...
		if (request.method === "GET" && pathname === callbackPath) {
			const token = url.searchParams.get("token");
			if (!token) {
				return new Response(JSON.stringify({ error: "Missing token parameter" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			const result = await verify(token);
			if (!result) {
				return new Response(JSON.stringify({ error: "Invalid or expired magic link" }), {
					status: 401,
					headers: { "Content-Type": "application/json" },
				});
			}

			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		return null;
	}

	return { sendLink, verify, handleRequest };
}
