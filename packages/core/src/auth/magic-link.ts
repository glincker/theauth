/**
 * Magic link authentication for TheAuth.
 * When the link is clicked the token is verified, the user is found or created, and a session is returned.
 *
 * @example
 * ```typescript
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
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
 * const response = await theauth.magicLink.handleRequest(request);
 * if (response) return response;
 * ```
 */

import { eq } from "drizzle-orm";
import { generateId, randomBytesHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { magicLinks, users } from "../db/schema.js";
import { singleUseFor } from "../db/store/for-database.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import { parseRememberMe } from "../plugin/helpers.js";
import type { SessionManager } from "../session/session.js";
import type { ClaimOptions } from "./email-claim.js";
import { claimVerifiedMailbox } from "./email-claim.js";
import { normalizeEmail } from "./normalize-email.js";
import type { SignInGate } from "./sign-in-gate.js";
import { createSignInGate, SignInGateError, signInGateResponse } from "./sign-in-gate.js";

export interface MagicLinkConfig extends ClaimOptions {
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
	 * Verify a magic link token and create a session. Returns null when the token is invalid, expired, or already used. Throws `SignInGateError` when the sign-in gate requires a forced password change or a second factor first (the link is consumed; finish with the challenge on the error).
	 */
	verify: (
		token: string,
		context?: { request?: Request; rememberMe?: boolean },
	) => Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date; rememberMe?: boolean };
	} | null>;
	/**
	 * Handle an incoming HTTP request.
	 * - `POST /auth/magic-link/send`, JSON body `{ email: string }`
	 * - `GET  /auth/magic-link/verify?token=<token>` Returns null when the path does not match (so callers can fall through to other handlers).
	 */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// Defaults

const DEFAULT_EXPIRY_SECONDS = 900; // 15 minutes
const DEFAULT_CALLBACK_PATH = "/auth/magic-link/verify";

export function createMagicLinkModule(
	config: MagicLinkConfig,
	db: Database,
	sessionManager: SessionManager,
	signInGate?: SignInGate,
	databaseHooks: DatabaseHookRunner = createDatabaseHookRunner(undefined),
): MagicLinkModule {
	const gate = signInGate ?? createSignInGate({ db });
	const tokenExpiry = config.tokenExpiry ?? DEFAULT_EXPIRY_SECONDS;
	const callbackPath = config.callbackPath ?? DEFAULT_CALLBACK_PATH;

	/** Find an existing user by email or create a new one. */
	async function findOrCreateUser(email: string): Promise<{ id: string; email: string }> {
		const existing = await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(eq(users.email, email));

		if (existing[0]) return { id: existing[0].id, email: existing[0].email };

		const id = databaseHooks.newId("user");
		const now = new Date();
		let storedEmail = email;
		let storedName: string | null = null;
		let storedMetadata: Record<string, unknown> | null = null;
		if (databaseHooks.has("user", "create")) {
			const hooked = await databaseHooks.before("user", "create", {
				id,
				email,
				name: null,
				metadata: null,
			});
			storedEmail = hooked.email;
			storedName = hooked.name;
			storedMetadata = hooked.metadata;
		}
		await db.insert(users).values({
			id,
			email: storedEmail,
			name: storedName,
			...(storedMetadata ? { metadata: storedMetadata } : {}),
			createdAt: now,
			updatedAt: now,
		});
		await databaseHooks.after("user", "create", {
			id,
			email: storedEmail,
			name: storedName,
			metadata: storedMetadata,
		});

		return { id, email: storedEmail };
	}

	async function sendLink(rawEmail: string): Promise<{ sent: boolean }> {
		const email = normalizeEmail(rawEmail);
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

	async function verify(
		token: string,
		context?: { request?: Request; rememberMe?: boolean },
	): Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date; rememberMe?: boolean };
	} | null> {
		const now = new Date();

		// Claim the link with one conditional UPDATE so two concurrent requests
		// cannot both redeem it: only the caller whose UPDATE flips used=false wins.
		// The email is read first because MySQL has no RETURNING to hand it back.
		const [link] = await db
			.select({ email: magicLinks.email })
			.from(magicLinks)
			.where(eq(magicLinks.token, token));
		if (!link) return null;
		if (!(await singleUseFor(db).magicLinks.markUsed(token, now))) return null;

		const user = await findOrCreateUser(link.email);
		await claimVerifiedMailbox(db, user.id, config, (id) => sessionManager.revokeAll(id));
		const decision = await gate.evaluate({
			userId: user.id,
			method: "magic_link",
			...(context?.request && { request: context.request }),
		});
		if (decision.action !== "allow") throw new SignInGateError(decision);

		const { token: sessionToken, session } = await sessionManager.create(user.id, undefined, {
			authMethods: ["otp"],
			...(context?.rememberMe !== undefined && { rememberMe: context.rememberMe }),
		});

		return {
			user,
			session: {
				token: sessionToken,
				expiresAt: session.expiresAt,
				...(session.rememberMe !== undefined && { rememberMe: session.rememberMe }),
			},
		};
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname;

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

			const email = normalizeEmail(String((body as Record<string, unknown>).email));
			const result = await sendLink(email);
			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (request.method === "GET" && pathname === callbackPath) {
			const token = url.searchParams.get("token");
			if (!token) {
				return new Response(JSON.stringify({ error: "Missing token parameter" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			let result: Awaited<ReturnType<typeof verify>>;
			try {
				const rememberMe = parseRememberMe(url.searchParams.get("rememberMe"));
				result = await verify(token, { request, ...(rememberMe !== undefined && { rememberMe }) });
			} catch (err) {
				if (err instanceof SignInGateError) return signInGateResponse(err);
				throw err;
			}
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
