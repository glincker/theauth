/**
 * Tests for magic link authentication.
 *
 * Covers:
 * - sendLink: creates a token record, calls sendMagicLink with the right URL
 * - verify: returns user + session on valid token
 * - verify: returns null for an expired token
 * - verify: returns null for an already-used token
 * - verify: returns null for an unknown token
 * - handleRequest: POST /auth/magic-link/send responds 200
 * - handleRequest: GET  /auth/magic-link/verify?token=... responds 200
 * - handleRequest: GET  /auth/magic-link/verify?token=... responds 401 for bad token
 * - handleRequest: returns null for unmatched paths
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MagicLinkModule } from "../src/auth/magic-link.js";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { magicLinks } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const APP_URL = "https://app.example.com";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeSendMagicLink() {
	return vi.fn(async (_email: string, _token: string, _url: string) => {
		// no-op in tests
	});
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("MagicLinkModule.sendLink", () => {
	let db: Database;
	let mod: MagicLinkModule;
	let sendMagicLink: ReturnType<typeof makeSendMagicLink>;

	beforeEach(async () => {
		db = await createTestDb();
		sendMagicLink = makeSendMagicLink();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMagicLinkModule({ sendMagicLink, appUrl: APP_URL }, db, sessionManager);
	});

	it("returns { sent: true } on success", async () => {
		const result = await mod.sendLink("alice@example.com");
		expect(result).toEqual({ sent: true });
	});

	it("calls sendMagicLink with the right email and a URL containing the token", async () => {
		await mod.sendLink("alice@example.com");

		expect(sendMagicLink).toHaveBeenCalledOnce();
		const [calledEmail, calledToken, calledUrl] = sendMagicLink.mock.calls[0] as [
			string,
			string,
			string,
		];
		expect(calledEmail).toBe("alice@example.com");
		expect(calledToken).toMatch(/^[0-9a-f]{64}$/);
		expect(calledUrl).toBe(`${APP_URL}/auth/magic-link/verify?token=${calledToken}`);
	});

	it("persists a magic link record to the database", async () => {
		await mod.sendLink("bob@example.com");

		const rows = await db.select().from(magicLinks).all();

		expect(rows).toHaveLength(1);
		expect(rows[0]?.email).toBe("bob@example.com");
		expect(rows[0]?.used).toBe(false);
	});

	it("creates the user in theauth_users if they do not exist yet", async () => {
		const { users } = await import("../src/db/schema.js");
		await mod.sendLink("newuser@example.com");

		const userRows = await db.select().from(users).all();

		expect(userRows.some((u) => u.email === "newuser@example.com")).toBe(true);
	});
});

describe("MagicLinkModule.verify", () => {
	let db: Database;
	let mod: MagicLinkModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMagicLinkModule(
			{ sendMagicLink: makeSendMagicLink(), appUrl: APP_URL },
			db,
			sessionManager,
		);
	});

	it("returns user and session for a valid token", async () => {
		let capturedToken = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMagicLinkModule(
			{
				sendMagicLink: async (_e, token) => {
					capturedToken = token;
				},
				appUrl: APP_URL,
			},
			db,
			sessionManager,
		);

		await mod.sendLink("carol@example.com");
		const result = await mod.verify(capturedToken);

		expect(result).not.toBeNull();
		expect(result?.user.email).toBe("carol@example.com");
		expect(result?.session.token).toBeTruthy();
		expect(result?.session.expiresAt).toBeInstanceOf(Date);
		expect(result?.session.expiresAt.getTime()).toBeGreaterThan(Date.now());
	});

	it("returns null for an unknown token", async () => {
		const result = await mod.verify("0".repeat(64));
		expect(result).toBeNull();
	});

	it("returns null when the token has already been used", async () => {
		let capturedToken = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMagicLinkModule(
			{
				sendMagicLink: async (_e, token) => {
					capturedToken = token;
				},
				appUrl: APP_URL,
			},
			db,
			sessionManager,
		);

		await mod.sendLink("dave@example.com");
		await mod.verify(capturedToken); // first use succeeds
		const result = await mod.verify(capturedToken); // replay
		expect(result).toBeNull();
	});

	it("returns null for an expired token", async () => {
		let capturedToken = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		// tokenExpiry of 0 seconds makes the token immediately expired.
		mod = createMagicLinkModule(
			{
				sendMagicLink: async (_e, token) => {
					capturedToken = token;
				},
				appUrl: APP_URL,
				tokenExpiry: 0,
			},
			db,
			sessionManager,
		);

		await mod.sendLink("eve@example.com");
		// Expire the token by back-dating it in the DB.
		db.update(magicLinks)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.run();

		const result = await mod.verify(capturedToken);
		expect(result).toBeNull();
	});
});

describe("MagicLinkModule.handleRequest", () => {
	let db: Database;
	let mod: MagicLinkModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMagicLinkModule(
			{ sendMagicLink: makeSendMagicLink(), appUrl: APP_URL },
			db,
			sessionManager,
		);
	});

	it("POST /auth/magic-link/send returns 200 with { sent: true }", async () => {
		const req = new Request("https://app.example.com/auth/magic-link/send", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "frank@example.com" }),
		});

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(200);
		const body = await response?.json();
		expect(body).toEqual({ sent: true });
	});

	it("POST /auth/magic-link/send returns 400 when email is missing", async () => {
		const req = new Request("https://app.example.com/auth/magic-link/send", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(400);
	});

	it("GET /auth/magic-link/verify?token=... returns 200 on valid token", async () => {
		let capturedToken = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMagicLinkModule(
			{
				sendMagicLink: async (_e, token) => {
					capturedToken = token;
				},
				appUrl: APP_URL,
			},
			db,
			sessionManager,
		);

		await mod.sendLink("grace@example.com");

		const req = new Request(
			`https://app.example.com/auth/magic-link/verify?token=${capturedToken}`,
		);
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(200);
		const body = await response?.json();
		expect(body.user.email).toBe("grace@example.com");
	});

	it("GET /auth/magic-link/verify?token=... returns 401 for an invalid token", async () => {
		const req = new Request(
			`https://app.example.com/auth/magic-link/verify?token=${"bad".repeat(20)}`,
		);
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(401);
	});

	it("returns null for unmatched paths", async () => {
		const req = new Request("https://app.example.com/something-else");
		const response = await mod.handleRequest(req);
		expect(response).toBeNull();
	});
});
