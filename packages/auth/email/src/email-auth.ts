import { randomBytes, randomUUID } from "node:crypto";
import type { Database } from "kavachos";
import { EmailAuthError, ErrorCodes } from "./errors.js";
import { hashPassword, validatePasswordStrength, verifyPassword } from "./password.js";
import type {
	EmailAuthConfig,
	EmailAuthModule,
	EmailUser,
	PasswordConfig,
	SignInInput,
	SignUpInput,
} from "./types.js";

// ---------------------------------------------------------------------------
// Email validation
// ---------------------------------------------------------------------------

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(email: string): boolean {
	return EMAIL_REGEX.test(email);
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

function generateUserId(): string {
	return `usr_${randomUUID().replace(/-/g, "")}`;
}

function generateAccountId(): string {
	return `eml_${randomUUID().replace(/-/g, "")}`;
}

function generateToken(): string {
	return randomBytes(32).toString("hex");
}

// ---------------------------------------------------------------------------
// Raw SQL helpers
// ---------------------------------------------------------------------------

/**
 * Execute a raw SQL statement against the underlying SQLite connection.
 * Uses the same pattern as kavachos/packages/core/src/db/migrations.ts.
 */
function execRaw(db: Database, sql: string): void {
	// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
	const session = (db as any).session;
	if (session?.client?.exec) {
		session.client.exec(sql);
	} else {
		// biome-ignore lint/suspicious/noExplicitAny: fallback raw execution
		(db as any).run(sql);
	}
}

function queryRaw(db: Database, sql: string, params: unknown[] = []): unknown[] {
	// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw queries
	const session = (db as any).session;
	const client = session?.client;
	if (!client?.prepare) return [];

	const stmt = client.prepare(sql);

	// sql.js statements expose getAsObject; better-sqlite3 statements do not.
	if (typeof stmt.getAsObject === "function") {
		try {
			if (params.length > 0) stmt.bind(params);
			const rows: unknown[] = [];
			while (stmt.step()) {
				rows.push(stmt.getAsObject());
			}
			return rows;
		} finally {
			if (typeof stmt.free === "function") stmt.free();
		}
	}

	// better-sqlite3: stmt.all(...spread)
	if (typeof stmt.all === "function") {
		return stmt.all(...params) as unknown[];
	}

	return [];
}

function runRaw(db: Database, sql: string, params: unknown[] = []): void {
	// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw mutations
	const session = (db as any).session;
	const client = session?.client;
	if (!client?.prepare) return;

	const stmt = client.prepare(sql);

	// sql.js path detected via getAsObject; expects an array of params.
	if (typeof stmt.getAsObject === "function") {
		try {
			if (params.length > 0) stmt.bind(params);
			stmt.step();
		} finally {
			if (typeof stmt.free === "function") stmt.free();
		}
		return;
	}

	// better-sqlite3: stmt.run(...spread)
	if (typeof stmt.run === "function") {
		stmt.run(...params);
	}
}

// ---------------------------------------------------------------------------
// Table initialisation
// ---------------------------------------------------------------------------

function initTables(db: Database): void {
	execRaw(
		db,
		`
CREATE TABLE IF NOT EXISTS kavach_email_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES kavach_users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  verification_token TEXT,
  verification_expires INTEGER,
  reset_token TEXT,
  reset_expires INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_accounts_user_id
  ON kavach_email_accounts(user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_accounts_verification_token
  ON kavach_email_accounts(verification_token)
  WHERE verification_token IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_accounts_reset_token
  ON kavach_email_accounts(reset_token)
  WHERE reset_token IS NOT NULL;
`,
	);
}

// ---------------------------------------------------------------------------
// Row → domain type helpers
// ---------------------------------------------------------------------------

interface UserRow {
	id: string;
	email: string;
	name: string | null;
	created_at: number;
	updated_at: number;
}

interface AccountRow {
	id: string;
	user_id: string;
	password_hash: string;
	email_verified: number;
	verification_token: string | null;
	verification_expires: number | null;
	reset_token: string | null;
	reset_expires: number | null;
	created_at: number;
	updated_at: number;
}

function rowToEmailUser(user: UserRow, account: AccountRow): EmailUser {
	return {
		id: user.id,
		email: user.email,
		name: user.name,
		emailVerified: account.email_verified === 1,
		createdAt: new Date(user.created_at),
		updatedAt: new Date(user.updated_at),
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an email+password authentication module backed by the KavachOS database.
 *
 * @param config - Email auth configuration (callbacks, password policy, URLs).
 * @param db     - The KavachOS Drizzle database instance.
 */
export function createEmailAuth(config: EmailAuthConfig, db: Database): EmailAuthModule {
	// Resolve config with defaults
	const passwordConfig: PasswordConfig = {
		minLength: config.password?.minLength ?? 8,
		maxLength: config.password?.maxLength ?? 128,
		requireUppercase: config.password?.requireUppercase ?? false,
		requireNumber: config.password?.requireNumber ?? false,
		requireSpecial: config.password?.requireSpecial ?? false,
	};
	const verificationExpiry = config.verificationExpiry ?? 86400; // 24h
	const resetExpiry = config.resetExpiry ?? 3600; // 1h
	const requireVerification = config.requireVerification ?? true;

	// Initialise the email accounts table
	initTables(db);

	// ── helpers ──────────────────────────────────────────────────────────────

	function findUserByEmail(email: string): { user: UserRow; account: AccountRow } | null {
		const rows = queryRaw(
			db,
			`SELECT u.id, u.email, u.name, u.created_at, u.updated_at,
			        a.id as account_id, a.user_id, a.password_hash, a.email_verified,
			        a.verification_token, a.verification_expires,
			        a.reset_token, a.reset_expires,
			        a.created_at as account_created_at, a.updated_at as account_updated_at
			 FROM kavach_users u
			 INNER JOIN kavach_email_accounts a ON a.user_id = u.id
			 WHERE u.email = ?`,
			[email],
		) as Array<Record<string, unknown>>;

		const row = rows[0];
		if (!row) return null;

		const user: UserRow = {
			id: row.id as string,
			email: row.email as string,
			name: (row.name as string | null) ?? null,
			created_at: row.created_at as number,
			updated_at: row.updated_at as number,
		};
		const account: AccountRow = {
			id: row.account_id as string,
			user_id: row.user_id as string,
			password_hash: row.password_hash as string,
			email_verified: row.email_verified as number,
			verification_token: (row.verification_token as string | null) ?? null,
			verification_expires: (row.verification_expires as number | null) ?? null,
			reset_token: (row.reset_token as string | null) ?? null,
			reset_expires: (row.reset_expires as number | null) ?? null,
			created_at: row.account_created_at as number,
			updated_at: row.account_updated_at as number,
		};
		return { user, account };
	}

	function findUserById(userId: string): { user: UserRow; account: AccountRow } | null {
		const rows = queryRaw(
			db,
			`SELECT u.id, u.email, u.name, u.created_at, u.updated_at,
			        a.id as account_id, a.user_id, a.password_hash, a.email_verified,
			        a.verification_token, a.verification_expires,
			        a.reset_token, a.reset_expires,
			        a.created_at as account_created_at, a.updated_at as account_updated_at
			 FROM kavach_users u
			 INNER JOIN kavach_email_accounts a ON a.user_id = u.id
			 WHERE u.id = ?`,
			[userId],
		) as Array<Record<string, unknown>>;

		const row = rows[0];
		if (!row) return null;

		const user: UserRow = {
			id: row.id as string,
			email: row.email as string,
			name: (row.name as string | null) ?? null,
			created_at: row.created_at as number,
			updated_at: row.updated_at as number,
		};
		const account: AccountRow = {
			id: row.account_id as string,
			user_id: row.user_id as string,
			password_hash: row.password_hash as string,
			email_verified: row.email_verified as number,
			verification_token: (row.verification_token as string | null) ?? null,
			verification_expires: (row.verification_expires as number | null) ?? null,
			reset_token: (row.reset_token as string | null) ?? null,
			reset_expires: (row.reset_expires as number | null) ?? null,
			created_at: row.account_created_at as number,
			updated_at: row.account_updated_at as number,
		};
		return { user, account };
	}

	// ── createSession helper (simple bearer token stored in kavach_sessions) ─

	function createSessionRecord(userId: string): { token: string; expiresAt: Date } {
		const sessionId = randomUUID();
		const expiresAt = new Date(Date.now() + 60 * 60 * 24 * 7 * 1000); // 7 days
		const now = new Date();

		runRaw(
			db,
			`INSERT INTO kavach_sessions (id, user_id, expires_at, metadata, created_at)
			 VALUES (?, ?, ?, NULL, ?)`,
			[sessionId, userId, expiresAt.getTime(), now.getTime()],
		);

		return { token: sessionId, expiresAt };
	}

	function revokeAllSessions(userId: string): void {
		runRaw(db, `DELETE FROM kavach_sessions WHERE user_id = ?`, [userId]);
	}

	// ── signUp ────────────────────────────────────────────────────────────────

	async function signUp(input: SignUpInput): Promise<{ user: EmailUser; token: string }> {
		if (!isValidEmail(input.email)) {
			throw new EmailAuthError(ErrorCodes.INVALID_EMAIL, "Invalid email address.");
		}

		const strength = validatePasswordStrength(input.password, passwordConfig);
		if (!strength.valid) {
			throw new EmailAuthError(
				ErrorCodes.INVALID_PASSWORD,
				strength.reason ?? "Password does not meet requirements.",
			);
		}

		// Check for duplicate
		const existing = findUserByEmail(input.email);
		if (existing) {
			throw new EmailAuthError(
				ErrorCodes.DUPLICATE_EMAIL,
				"An account with this email already exists.",
			);
		}

		const userId = generateUserId();
		const accountId = generateAccountId();
		const now = Date.now();
		const passwordHash = await hashPassword(input.password);

		// Insert user
		runRaw(
			db,
			`INSERT INTO kavach_users (id, email, name, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?)`,
			[userId, input.email, input.name ?? null, now, now],
		);

		// Generate verification token
		const verificationToken = generateToken();
		const verificationExpires = now + verificationExpiry * 1000;

		// Insert email account
		runRaw(
			db,
			`INSERT INTO kavach_email_accounts
			   (id, user_id, password_hash, email_verified, verification_token, verification_expires, created_at, updated_at)
			 VALUES (?, ?, ?, 0, ?, ?, ?, ?)`,
			[accountId, userId, passwordHash, verificationToken, verificationExpires, now, now],
		);

		const verificationUrl = `${config.appUrl}/auth/verify-email?token=${verificationToken}`;
		await config.sendVerificationEmail(input.email, verificationToken, verificationUrl);

		const { token } = createSessionRecord(userId);

		const emailUser: EmailUser = {
			id: userId,
			email: input.email,
			name: input.name ?? null,
			emailVerified: false,
			createdAt: new Date(now),
			updatedAt: new Date(now),
		};

		return { user: emailUser, token };
	}

	// ── signIn ────────────────────────────────────────────────────────────────

	async function signIn(
		input: SignInInput,
	): Promise<{ user: EmailUser; session: { token: string; expiresAt: Date } }> {
		const result = findUserByEmail(input.email);

		if (!result) {
			throw new EmailAuthError(ErrorCodes.INVALID_CREDENTIALS, "Invalid email or password.");
		}

		const { user, account } = result;

		const passwordOk = await verifyPassword(input.password, account.password_hash);
		if (!passwordOk) {
			throw new EmailAuthError(ErrorCodes.INVALID_CREDENTIALS, "Invalid email or password.");
		}

		if (requireVerification && account.email_verified !== 1) {
			throw new EmailAuthError(
				ErrorCodes.EMAIL_NOT_VERIFIED,
				"Email address has not been verified. Check your inbox.",
			);
		}

		const session = createSessionRecord(user.id);

		return {
			user: rowToEmailUser(user, account),
			session,
		};
	}

	// ── verifyEmail ───────────────────────────────────────────────────────────

	async function verifyEmail(token: string): Promise<{ verified: boolean }> {
		const rows = queryRaw(
			db,
			`SELECT id, user_id, verification_expires
			 FROM kavach_email_accounts
			 WHERE verification_token = ?`,
			[token],
		) as Array<Record<string, unknown>>;

		const row = rows[0];
		if (!row) {
			throw new EmailAuthError(ErrorCodes.INVALID_TOKEN, "Verification token is invalid.");
		}

		const expires = row.verification_expires as number | null;
		if (expires === null || Date.now() > expires) {
			throw new EmailAuthError(ErrorCodes.TOKEN_EXPIRED, "Verification token has expired.");
		}

		const now = Date.now();
		runRaw(
			db,
			`UPDATE kavach_email_accounts
			 SET email_verified = 1, verification_token = NULL, verification_expires = NULL, updated_at = ?
			 WHERE id = ?`,
			[now, row.id as string],
		);

		return { verified: true };
	}

	// ── requestReset ──────────────────────────────────────────────────────────

	async function requestReset(email: string): Promise<void> {
		const result = findUserByEmail(email);
		if (!result) {
			// Silent return — do not reveal whether the email exists
			return;
		}

		const resetToken = generateToken();
		const resetExpires = Date.now() + resetExpiry * 1000;
		const now = Date.now();

		runRaw(
			db,
			`UPDATE kavach_email_accounts
			 SET reset_token = ?, reset_expires = ?, updated_at = ?
			 WHERE user_id = ?`,
			[resetToken, resetExpires, now, result.user.id],
		);

		const resetUrl = `${config.appUrl}/auth/reset-password?token=${resetToken}`;
		await config.sendResetEmail(email, resetToken, resetUrl);
	}

	// ── resetPassword ─────────────────────────────────────────────────────────

	async function resetPassword(token: string, newPassword: string): Promise<{ success: boolean }> {
		const rows = queryRaw(
			db,
			`SELECT id, user_id, reset_expires
			 FROM kavach_email_accounts
			 WHERE reset_token = ?`,
			[token],
		) as Array<Record<string, unknown>>;

		const row = rows[0];
		if (!row) {
			throw new EmailAuthError(ErrorCodes.INVALID_TOKEN, "Reset token is invalid.");
		}

		const expires = row.reset_expires as number | null;
		if (expires === null || Date.now() > expires) {
			throw new EmailAuthError(ErrorCodes.TOKEN_EXPIRED, "Reset token has expired.");
		}

		const strength = validatePasswordStrength(newPassword, passwordConfig);
		if (!strength.valid) {
			throw new EmailAuthError(
				ErrorCodes.INVALID_PASSWORD,
				strength.reason ?? "Password does not meet requirements.",
			);
		}

		const passwordHash = await hashPassword(newPassword);
		const userId = row.user_id as string;
		const now = Date.now();

		runRaw(
			db,
			`UPDATE kavach_email_accounts
			 SET password_hash = ?, reset_token = NULL, reset_expires = NULL, updated_at = ?
			 WHERE id = ?`,
			[passwordHash, now, row.id as string],
		);

		// Revoke all sessions as a security measure
		revokeAllSessions(userId);

		return { success: true };
	}

	// ── changePassword ────────────────────────────────────────────────────────

	async function changePassword(
		userId: string,
		currentPassword: string,
		newPassword: string,
	): Promise<{ success: boolean }> {
		const result = findUserById(userId);
		if (!result) {
			throw new EmailAuthError(ErrorCodes.USER_NOT_FOUND, "User not found.");
		}

		const { account } = result;

		const passwordOk = await verifyPassword(currentPassword, account.password_hash);
		if (!passwordOk) {
			throw new EmailAuthError(ErrorCodes.WRONG_PASSWORD, "Current password is incorrect.");
		}

		const strength = validatePasswordStrength(newPassword, passwordConfig);
		if (!strength.valid) {
			throw new EmailAuthError(
				ErrorCodes.INVALID_PASSWORD,
				strength.reason ?? "Password does not meet requirements.",
			);
		}

		const passwordHash = await hashPassword(newPassword);
		const now = Date.now();

		runRaw(
			db,
			`UPDATE kavach_email_accounts
			 SET password_hash = ?, updated_at = ?
			 WHERE user_id = ?`,
			[passwordHash, now, userId],
		);

		return { success: true };
	}

	// ── getUser ───────────────────────────────────────────────────────────────

	async function getUser(userId: string): Promise<EmailUser | null> {
		const result = findUserById(userId);
		if (!result) return null;
		return rowToEmailUser(result.user, result.account);
	}

	async function getUserByEmail(email: string): Promise<EmailUser | null> {
		const result = findUserByEmail(email);
		if (!result) return null;
		return rowToEmailUser(result.user, result.account);
	}

	// ── handleRequest ─────────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const path = url.pathname;
		const method = request.method.toUpperCase();

		if (method !== "POST") return null;

		function jsonOk(data: unknown, status = 200): Response {
			return new Response(JSON.stringify(data), {
				status,
				headers: { "Content-Type": "application/json" },
			});
		}

		function jsonError(code: string, message: string, status = 400): Response {
			return new Response(JSON.stringify({ error: { code, message } }), {
				status,
				headers: { "Content-Type": "application/json" },
			});
		}

		async function parseBody(): Promise<Record<string, unknown>> {
			try {
				return (await request.json()) as Record<string, unknown>;
			} catch {
				return {};
			}
		}

		try {
			if (path === "/auth/sign-up") {
				const body = await parseBody();
				const result = await signUp({
					email: String(body.email ?? ""),
					password: String(body.password ?? ""),
					name: body.name != null ? String(body.name) : undefined,
				});
				return jsonOk(result, 201);
			}

			if (path === "/auth/sign-in") {
				const body = await parseBody();
				const result = await signIn({
					email: String(body.email ?? ""),
					password: String(body.password ?? ""),
				});
				return jsonOk(result);
			}

			if (path === "/auth/verify-email") {
				const body = await parseBody();
				const result = await verifyEmail(String(body.token ?? ""));
				return jsonOk(result);
			}

			if (path === "/auth/forgot-password") {
				const body = await parseBody();
				await requestReset(String(body.email ?? ""));
				return jsonOk({ success: true });
			}

			if (path === "/auth/reset-password") {
				const body = await parseBody();
				const result = await resetPassword(
					String(body.token ?? ""),
					String(body.newPassword ?? ""),
				);
				return jsonOk(result);
			}

			if (path === "/auth/change-password") {
				const body = await parseBody();
				// Expect userId in header or body for now — caller handles auth
				const userId = String(body.userId ?? "");
				if (!userId) {
					return jsonError("UNAUTHORIZED", "Missing userId.", 401);
				}
				const result = await changePassword(
					userId,
					String(body.currentPassword ?? ""),
					String(body.newPassword ?? ""),
				);
				return jsonOk(result);
			}
		} catch (err) {
			if (err instanceof EmailAuthError) {
				const status =
					err.code === ErrorCodes.INVALID_CREDENTIALS || err.code === ErrorCodes.EMAIL_NOT_VERIFIED
						? 401
						: err.code === ErrorCodes.DUPLICATE_EMAIL
							? 409
							: err.code === ErrorCodes.USER_NOT_FOUND
								? 404
								: 400;
				return jsonError(err.code, err.message, status);
			}
			return jsonError("INTERNAL_ERROR", "An unexpected error occurred.", 500);
		}

		return null;
	}

	return {
		signUp,
		signIn,
		verifyEmail,
		requestReset,
		resetPassword,
		changePassword,
		getUser,
		getUserByEmail,
		handleRequest,
	};
}
