import { oauth } from "../../src/auth/oauth/plugin.js";
import type { Database } from "../../src/db/database.js";
import type { TheAuth } from "../../src/theauth.js";
import { createTheAuth } from "../../src/theauth.js";

export type Provider = "postgres" | "mysql";

export const SESSION_SECRET = "dialect-session-secret-that-is-at-least-32-chars!!";
export const HMAC_KEY = "dialect-audit-hmac-key";

/** Messages the email modules would have delivered. */
export interface Mailbox {
	magicTokens: string[];
	otpCodes: string[];
}

export interface Booted {
	auth: TheAuth;
	mail: Mailbox;
}

type Closable = { $client?: { end?: () => Promise<void> } };

/** Ends the driver pool behind a Drizzle handle, when it has one. */
export async function closeDatabase(db: Database): Promise<void> {
	await (db as unknown as Closable).$client?.end?.();
}

/** Boots createTheAuth against the dialect database with every module the suite exercises enabled. */
export function createCoreBooter(provider: Provider, url: string) {
	const opened: TheAuth[] = [];

	async function boot(): Promise<Booted> {
		const mail: Mailbox = { magicTokens: [], otpCodes: [] };
		const database = {
			provider,
			url,
			...(provider === "mysql" ? { experimental: true } : {}),
		};
		const auth = await createTheAuth({
			database,
			baseUrl: "https://auth.dialect.test",
			secret: SESSION_SECRET,
			agents: { enabled: true, maxPerUser: 50, auditAll: true, tokenExpiry: "24h" },
			audit: { tamperEvident: true, hmacKey: HMAC_KEY },
			auth: { session: { secret: SESSION_SECRET } },
			secondaryStorage: "database",
			magicLink: {
				appUrl: "https://app.dialect.test",
				sendMagicLink: async (_email, token) => {
					mail.magicTokens.push(token);
				},
			},
			emailOtp: {
				sendOtp: async (_email, code) => {
					mail.otpCodes.push(code);
				},
			},
			admin: { adminUserIds: ["admin-1"] },
			totp: { appName: "Dialect" },
			apiKeys: {},
			org: {},
			username: {},
			sso: {},
			phone: { sendSms: async () => {} },
			passkey: { rpName: "Dialect", rpId: "dialect.test", origin: "https://app.dialect.test" },
			passwordReset: {
				resetUrl: "https://app.dialect.test/reset",
				sendResetEmail: async () => {},
			},
			emailVerification: {
				verifyUrl: "https://app.dialect.test/verify",
				sendVerificationEmail: async () => {},
			},
			mcp: {
				enabled: true,
				issuer: "https://auth.dialect.test",
				baseUrl: "https://auth.dialect.test/api/auth",
				signingSecret: SESSION_SECRET,
			},
			plugins: [oauth({ providers: {} })],
		});
		opened.push(auth);
		return { auth, mail };
	}

	async function closeAll(): Promise<void> {
		for (const auth of opened.splice(0)) await closeDatabase(auth.db);
	}

	return { boot, closeAll };
}

export type CoreBooter = ReturnType<typeof createCoreBooter>;
