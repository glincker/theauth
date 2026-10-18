/**
 * Regression for the HTTP review: no auth handler may act on a `userId` taken from the request
 * body or query. Each acts on the signed-in user, refuses a foreign id, or answers 401.
 */

import { describe, expect, it } from "vitest";
import { additionalFields } from "../src/auth/additional-fields.js";
import { passkey } from "../src/auth/passkey-plugin.js";
import { users } from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const PASSKEY = {
	rpName: "Test App",
	rpId: "example.com",
	origin: "https://example.com",
	attestation: "none" as const,
	userVerification: "preferred" as const,
	challengeTimeout: 60_000,
};

type Auth = Awaited<ReturnType<typeof createTheAuth>>;

async function seed(auth: Auth, id: string): Promise<string> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now });
	const sessions = auth.auth.session;
	if (!sessions) throw new Error("session manager missing");
	return (await sessions.create(id)).token;
}

function json(method: string, url: string, body: unknown, token?: string): Request {
	return new Request(url, {
		method,
		headers: {
			"content-type": "application/json",
			...(token && { authorization: `Bearer ${token}` }),
		},
		body: JSON.stringify(body),
	});
}

describe("passkey plugin registration binds to the session user", () => {
	it("ignores a body userId and registers for the caller", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			plugins: [passkey(PASSKEY)],
		});
		const token = await seed(auth, "attacker");
		await seed(auth, "victim");
		const res = await auth.plugins.handleRequest(
			json(
				"POST",
				"https://example.com/auth/passkey/register/options",
				{ userId: "victim", userName: "victim" },
				token,
			),
		);
		expect(res?.status).toBe(200);
		const options = (await res?.json()) as { user: { id: string } };
		expect(options.user.id).toBe("attacker");
	});
});

describe("additionalFields user endpoints are self only", () => {
	async function setup() {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			plugins: [additionalFields({ user: { plan: { type: "string", required: false } } })],
		});
		const token = await seed(auth, "attacker");
		await seed(auth, "victim");
		return { auth, token };
	}

	it("refuses writing another user's fields", async () => {
		const { auth, token } = await setup();
		const res = await auth.plugins.handleRequest(
			json(
				"PUT",
				"http://localhost/auth/users/fields",
				{ userId: "victim", fields: { plan: "pwned" } },
				token,
			),
		);
		expect(res?.status).toBe(403);
	});

	it("refuses reading another user's fields", async () => {
		const { auth, token } = await setup();
		const res = await auth.plugins.handleRequest(
			new Request("http://localhost/auth/users/fields?userId=victim", {
				headers: { authorization: `Bearer ${token}` },
			}),
		);
		expect(res?.status).toBe(403);
	});
});

describe("headless module handlers wired by createTheAuth use the session", () => {
	async function setup() {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			totp: {},
			passkey: PASSKEY,
		});
		const token = await seed(auth, "attacker");
		await seed(auth, "victim");
		return { auth, token };
	}

	it("totp setup with a body userId and no session is 401", async () => {
		const { auth } = await setup();
		const res = await auth.totp?.handleRequest(
			json("POST", "http://localhost/auth/2fa/setup", { userId: "victim" }),
		);
		expect(res?.status).toBe(401);
	});

	it("totp setup with a session acts on the session user only", async () => {
		const { auth, token } = await setup();
		const res = await auth.totp?.handleRequest(
			json("POST", "http://localhost/auth/2fa/setup", { userId: "victim" }, token),
		);
		expect(res?.status).toBe(200);
		const body = (await res?.json()) as { uri: string };
		expect(body.uri).toContain("attacker");
		expect(body.uri).not.toContain("victim");
	});

	it("passkey module registration with no session is 401", async () => {
		const { auth } = await setup();
		const res = await auth.passkey?.handleRequest(
			json("POST", "https://example.com/auth/passkey/register/options", {
				userId: "victim",
				userName: "victim",
			}),
		);
		expect(res?.status).toBe(401);
	});
});
