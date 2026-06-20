/**
 * Username + password authentication for TheAuth.
 *
 * Users register with a username and password instead of email. Usernames are
 * normalised to lowercase by default. Passwords are hashed with scrypt before
 * storage so a database breach does not expose credentials.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   username: {
 *     password: { minLength: 8 },
 *   },
 * });
 *
 * const response = await kavach.username?.handleRequest(request);
 * if (response) return response;
 * ```
 */

import { and, eq } from "drizzle-orm";
import { generateId, pbkdf2Hash, pbkdf2Verify } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface UsernameAuthConfig {
	/** Minimum username length (default: 3) */
	minUsernameLength?: number;
	/** Maximum username length (default: 32) */
	maxUsernameLength?: number;
	/** Allowed characters pattern (default: /^[a-zA-Z0-9_-]+$/) */
	allowedPattern?: RegExp;
	/** Whether usernames are case-sensitive (default: false — normalise to lowercase) */
	caseSensitive?: boolean;
	password?: {
		/** Minimum password length (default: 8) */
		minLength?: number;
		/** Maximum password length (default: 128) */
		maxLength?: number;
	};
}

export interface UsernameAuthModule {
	signUp: (input: { username: string; password: string; name?: string }) => Promise<{
		user: { id: string; username: string; name: string | null };
		session: { token: string; expiresAt: Date };
	}>;
	signIn: (input: { username: string; password: string }) => Promise<{
		user: { id: string; username: string };
		session: { token: string; expiresAt: Date };
	}>;
	changePassword: (
		userId: string,
		current: string,
		newPassword: string,
	) => Promise<{ success: boolean }>;
	changeUsername: (userId: string, newUsername: string) => Promise<{ success: boolean }>;
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MIN_USERNAME = 3;
const DEFAULT_MAX_USERNAME = 32;
const DEFAULT_ALLOWED_PATTERN = /^[a-zA-Z0-9_-]+$/;
const DEFAULT_MIN_PASSWORD = 8;
const DEFAULT_MAX_PASSWORD = 128;
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function hashPassword(password: string): Promise<string> {
	return pbkdf2Hash(password);
}

async function verifyPassword(stored: string, candidate: string): Promise<boolean> {
	return pbkdf2Verify(candidate, stored);
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createUsernameAuthModule(
	config: UsernameAuthConfig,
	db: Database,
	sessionManager: SessionManager,
): UsernameAuthModule {
	const minUsernameLen = config.minUsernameLength ?? DEFAULT_MIN_USERNAME;
	const maxUsernameLen = config.maxUsernameLength ?? DEFAULT_MAX_USERNAME;
	const allowedPattern = config.allowedPattern ?? DEFAULT_ALLOWED_PATTERN;
	const caseSensitive = config.caseSensitive ?? false;
	const minPasswordLen = config.password?.minLength ?? DEFAULT_MIN_PASSWORD;
	const maxPasswordLen = config.password?.maxLength ?? DEFAULT_MAX_PASSWORD;

	function normalise(username: string): string {
		return caseSensitive ? username : username.toLowerCase();
	}

	function validateUsername(username: string): string | null {
		if (username.length < minUsernameLen) {
			return `Username must be at least ${minUsernameLen} characters`;
		}
		if (username.length > maxUsernameLen) {
			return `Username must be at most ${maxUsernameLen} characters`;
		}
		if (!allowedPattern.test(username)) {
			return "Username contains invalid characters";
		}
		return null;
	}

	function validatePassword(password: string): string | null {
		if (password.length < minPasswordLen) {
			return `Password must be at least ${minPasswordLen} characters`;
		}
		if (password.length > maxPasswordLen) {
			return `Password must be at most ${maxPasswordLen} characters`;
		}
		return null;
	}

	// ── public API ─────────────────────────────────────────────────────────

	async function signUp(input: { username: string; password: string; name?: string }): Promise<{
		user: { id: string; username: string; name: string | null };
		session: { token: string; expiresAt: Date };
	}> {
		const normalisedUsername = normalise(input.username.trim());

		const usernameError = validateUsername(normalisedUsername);
		if (usernameError) throw new Error(usernameError);

		const passwordError = validatePassword(input.password);
		if (passwordError) throw new Error(passwordError);

		// Check username uniqueness
		const existing = await db
			.select({ id: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.username, normalisedUsername));

		if (existing[0]) throw new Error("Username already taken");

		const now = new Date();
		const userId = generateId();
		const passwordHash = await hashPassword(input.password);

		await db.insert(users).values({
			id: userId,
			email: `${normalisedUsername}@username.local`,
			name: input.name ?? null,
			createdAt: now,
			updatedAt: now,
		});

		await db.insert(usernameAccounts).values({
			id: generateId(),
			userId,
			username: normalisedUsername,
			passwordHash,
			createdAt: now,
			updatedAt: now,
		});

		const { token, session } = await sessionManager.create(userId);

		return {
			user: { id: userId, username: normalisedUsername, name: input.name ?? null },
			session: { token, expiresAt: session.expiresAt },
		};
	}

	async function signIn(input: { username: string; password: string }): Promise<{
		user: { id: string; username: string };
		session: { token: string; expiresAt: Date };
	}> {
		const normalisedUsername = normalise(input.username.trim());

		const rows = await db
			.select()
			.from(usernameAccounts)
			.where(eq(usernameAccounts.username, normalisedUsername));

		const account = rows[0];
		if (!account) throw new Error("Invalid username or password");

		const valid = await verifyPassword(account.passwordHash, input.password);
		if (!valid) throw new Error("Invalid username or password");

		const userRows = await db
			.select({ forcePasswordReset: users.forcePasswordReset })
			.from(users)
			.where(eq(users.id, account.userId));

		if (userRows[0]?.forcePasswordReset === 1) {
			throw new Error("Password reset required");
		}

		const { token, session } = await sessionManager.create(account.userId);

		return {
			user: { id: account.userId, username: normalisedUsername },
			session: { token, expiresAt: session.expiresAt },
		};
	}

	async function changePassword(
		userId: string,
		current: string,
		newPassword: string,
	): Promise<{ success: boolean }> {
		const rows = await db
			.select()
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, userId));

		const account = rows[0];
		if (!account) throw new Error("Account not found");

		const valid = await verifyPassword(account.passwordHash, current);
		if (!valid) throw new Error("Current password is incorrect");

		const passwordError = validatePassword(newPassword);
		if (passwordError) throw new Error(passwordError);

		const newHash = await hashPassword(newPassword);
		await db
			.update(usernameAccounts)
			.set({ passwordHash: newHash, updatedAt: new Date() })
			.where(eq(usernameAccounts.userId, userId));

		return { success: true };
	}

	async function changeUsername(
		userId: string,
		newUsername: string,
	): Promise<{ success: boolean }> {
		const normalised = normalise(newUsername.trim());

		const usernameError = validateUsername(normalised);
		if (usernameError) throw new Error(usernameError);

		const existing = await db
			.select({ id: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(and(eq(usernameAccounts.username, normalised)));

		if (existing[0] && existing[0].id !== userId) {
			throw new Error("Username already taken");
		}

		await db
			.update(usernameAccounts)
			.set({ username: normalised, updatedAt: new Date() })
			.where(eq(usernameAccounts.userId, userId));

		return { success: true };
	}

	const HANDLED_PATHS = new Set([
		"/auth/username/sign-up",
		"/auth/username/sign-in",
		"/auth/username/change-password",
		"/auth/username/change-username",
	]);

	async function handleRequest(request: Request): Promise<Response | null> {
		if (request.method !== "POST") return null;

		const url = new URL(request.url);
		const { pathname } = url;

		if (!HANDLED_PATHS.has(pathname)) return null;

		let body: unknown;
		try {
			body = await request.json();
		} catch {
			return jsonResponse({ error: "Invalid JSON body" }, 400);
		}

		const b = body as Record<string, unknown>;

		if (pathname === "/auth/username/sign-up") {
			if (typeof b.username !== "string" || typeof b.password !== "string") {
				return jsonResponse({ error: "Missing required fields: username, password" }, 400);
			}
			try {
				const result = await signUp({
					username: b.username,
					password: b.password,
					name: typeof b.name === "string" ? b.name : undefined,
				});
				return jsonResponse(result, 201);
			} catch (err) {
				return jsonResponse({ error: err instanceof Error ? err.message : "Sign-up failed" }, 400);
			}
		}

		if (pathname === "/auth/username/sign-in") {
			if (typeof b.username !== "string" || typeof b.password !== "string") {
				return jsonResponse({ error: "Missing required fields: username, password" }, 400);
			}
			try {
				const result = await signIn({ username: b.username, password: b.password });
				return jsonResponse(result);
			} catch (err) {
				if (err instanceof Error && err.message === "Password reset required") {
					return jsonResponse(
						{
							error: {
								code: "PASSWORD_RESET_REQUIRED",
								message: "You must reset your password before signing in",
							},
						},
						403,
					);
				}
				return jsonResponse({ error: "Invalid username or password" }, 401);
			}
		}

		if (pathname === "/auth/username/change-password") {
			if (
				typeof b.userId !== "string" ||
				typeof b.current !== "string" ||
				typeof b.newPassword !== "string"
			) {
				return jsonResponse(
					{ error: "Missing required fields: userId, current, newPassword" },
					400,
				);
			}
			try {
				const result = await changePassword(b.userId, b.current, b.newPassword);
				return jsonResponse(result);
			} catch (err) {
				return jsonResponse(
					{ error: err instanceof Error ? err.message : "Change password failed" },
					400,
				);
			}
		}

		if (pathname === "/auth/username/change-username") {
			if (typeof b.userId !== "string" || typeof b.newUsername !== "string") {
				return jsonResponse({ error: "Missing required fields: userId, newUsername" }, 400);
			}
			try {
				const result = await changeUsername(b.userId, b.newUsername);
				return jsonResponse(result);
			} catch (err) {
				return jsonResponse(
					{ error: err instanceof Error ? err.message : "Change username failed" },
					400,
				);
			}
		}

		return null;
	}

	return { signUp, signIn, changePassword, changeUsername, handleRequest };
}
