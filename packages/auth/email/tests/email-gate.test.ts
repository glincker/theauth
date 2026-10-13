import { describe, expect, it } from "vitest";
import { eq } from "../../../core/node_modules/drizzle-orm/index.js";
import { createSignInGate } from "../../../core/src/auth/sign-in-gate.js";
import { createDatabase } from "../../../core/src/db/database.js";
import { createTables } from "../../../core/src/db/migrations.js";
import { sessions, users } from "../../../core/src/db/schema.js";
import { createEmailAuth } from "../src/email-auth.js";
import { EmailAuthError, ErrorCodes } from "../src/errors.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function setup(options: { factorUsers?: () => string[]; sessionLimit?: object } = {}) {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const gate = createSignInGate({
		db,
		sessionSecret: SECRET,
		config: {
			factors: [
				{
					id: "fake",
					isEnabled: async (id) => (options.factorUsers?.() ?? []).includes(id),
					verify: async (_id, code) => code === "123456",
				},
			],
		},
	});
	const auth = createEmailAuth(
		{
			sendVerificationEmail: async () => {},
			sendResetEmail: async () => {},
			appUrl: "https://app.example.com",
			requireVerification: false,
			signInGate: gate,
			...(options.sessionLimit && { sessionLimit: options.sessionLimit }),
		},
		db,
	);
	return { db, gate, auth };
}

describe("email sign-in gate", () => {
	it("forced password change yields a completable challenge", async () => {
		const { db, gate, auth } = await setup();
		const { user } = await auth.signUp({ email: "a@example.com", password: "Password123" });
		await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, user.id));

		const err = await auth
			.signIn({ email: "a@example.com", password: "Password123" })
			.catch((e) => e);
		expect(err).toBeInstanceOf(EmailAuthError);
		expect((err as EmailAuthError).code).toBe(ErrorCodes.PASSWORD_RESET_REQUIRED);
		const challenge = String((err as EmailAuthError).details?.challenge);

		const done = await gate.completePasswordChange({ challenge, newPassword: "NewPassword456" });
		expect(done).toMatchObject({ ok: true, next: { action: "allow" } });

		const signedIn = await auth.signIn({ email: "a@example.com", password: "NewPassword456" });
		expect(signedIn.session.token).toBeTruthy();
	});

	it("requires 2FA when the gate says so and answers over HTTP", async () => {
		let enabled: string[] = [];
		const { gate, auth } = await setup({ factorUsers: () => enabled });
		const { user } = await auth.signUp({ email: "b@example.com", password: "Password123" });
		enabled = [user.id];

		const res = await auth.handleRequest(
			new Request("https://app.example.com/auth/sign-in", {
				method: "POST",
				body: JSON.stringify({ email: "b@example.com", password: "Password123" }),
			}),
		);
		expect(res?.status).toBe(200);
		const body = (await res?.json()) as { twoFactorRequired: boolean; challenge: string };
		expect(body.twoFactorRequired).toBe(true);
		const done = await gate.completeTwoFactor({ challenge: body.challenge, code: "123456" });
		expect(done).toMatchObject({ ok: true, userId: user.id });
	});

	it("evicts or rejects at the session limit", async () => {
		const { auth } = await setup({ sessionLimit: { maxConcurrent: 1, onLimit: "reject" } });
		await auth.signUp({ email: "c@example.com", password: "Password123" });
		const err = await auth
			.signIn({ email: "c@example.com", password: "Password123" })
			.catch((e) => e);
		expect(err).toBeInstanceOf(EmailAuthError);
		expect((err as EmailAuthError).code).toBe(ErrorCodes.SESSION_LIMIT_REACHED);
	});

	it("evict-oldest keeps a single session", async () => {
		const { db, auth } = await setup({ sessionLimit: { maxConcurrent: 1 } });
		const { user } = await auth.signUp({ email: "d@example.com", password: "Password123" });
		await auth.signIn({ email: "d@example.com", password: "Password123" });
		const rows = await db.select().from(sessions).where(eq(sessions.userId, user.id));
		expect(rows.length).toBe(1);
	});
});
