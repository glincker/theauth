/**
 * Authentication context for step-up (RFC 9470): derived amr, acr and auth_time, freshness per class,
 * the WWW-Authenticate challenge, and how the session manager records and keeps events.
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import type { AuthEvent } from "../src/session/auth-context.js";
import {
	ACR,
	ACR_ORDER,
	authMethodsForSignIn,
	buildStepUpChallenge,
	evaluateAuthRequirement,
	normalizeEvents,
	recordAuthEvent,
	resolveAuthContext,
} from "../src/session/auth-context.js";
import { createCookieSessionManager } from "../src/session/manager.js";
import { createSessionManager } from "../src/session/session.js";

const NOW = 1_800_000_000;
const ev = (method: AuthEvent["method"], ago: number): AuthEvent => ({ method, at: NOW - ago });

describe("resolveAuthContext", () => {
	it("reports none for a session with no recorded events and falls back to the session start", () => {
		const ctx = resolveAuthContext([], NOW - 500);
		expect(ctx.acr).toBe(ACR.none);
		expect(ctx.amr).toEqual([]);
		expect(ctx.authTime).toBe(NOW - 500);
	});

	it("rates a password alone as single factor", () => {
		const ctx = resolveAuthContext([ev("password", 10)], NOW);
		expect(ctx.acr).toBe(ACR.singleFactor);
		expect(ctx.amr).toEqual(["pwd"]);
	});

	it("rates a password plus a TOTP code as multi factor and adds mfa to amr", () => {
		const ctx = resolveAuthContext([ev("password", 100), ev("totp", 5)], NOW);
		expect(ctx.acr).toBe(ACR.mfa);
		expect(ctx.amr).toEqual(["mfa", "otp", "pwd"]);
		expect(ctx.authTime).toBe(NOW - 5);
	});

	it("does not count two possession codes as multi factor", () => {
		expect(resolveAuthContext([ev("otp", 10), ev("totp", 5)], NOW).acr).toBe(ACR.singleFactor);
	});

	it("rates a user verified passkey as phishing resistant on its own", () => {
		const ctx = resolveAuthContext([ev("passkey", 1)], NOW);
		expect(ctx.acr).toBe(ACR.phishingResistant);
		expect(ctx.amr).toEqual(["mfa", "swk", "user"]);
	});

	it("rates a passkey without user verification as single factor", () => {
		expect(resolveAuthContext([ev("passkey_presence", 1)], NOW).acr).toBe(ACR.singleFactor);
	});

	it("keeps one event per method and drops malformed stored data", () => {
		const events = normalizeEvents([
			{ method: "password", at: 5 },
			{ method: "password", at: 9 },
			{ method: "bogus", at: 1 },
			{ method: "totp", at: "x" },
			null,
			"string",
		]);
		expect(events).toEqual([{ method: "password", at: 9 }]);
		expect(normalizeEvents("nope")).toEqual([]);
	});

	it("replaces an older event of the same method when one is recorded again", () => {
		const events = recordAuthEvent([ev("password", 100), ev("totp", 50)], "totp", NOW);
		expect(events[0]).toEqual({ method: "totp", at: NOW });
		expect(events).toHaveLength(2);
	});

	it("maps sign-in methods to authentication methods", () => {
		expect(authMethodsForSignIn("password")).toEqual(["password"]);
		expect(authMethodsForSignIn("magic_link")).toEqual(["otp"]);
		expect(authMethodsForSignIn("social")).toEqual(["federated"]);
		expect(authMethodsForSignIn("siwe")).toEqual([]);
	});
});

describe("evaluateAuthRequirement", () => {
	it("passes when no requirement is set", () => {
		expect(evaluateAuthRequirement(null, {}, NOW)).toEqual({ ok: true });
	});

	it("lets a stronger class satisfy a weaker request", () => {
		const a = { acr: ACR.phishingResistant, authTime: NOW };
		expect(evaluateAuthRequirement(a, { acr: ACR.mfa }, NOW)).toEqual({ ok: true });
		expect(evaluateAuthRequirement(a, { acr: [ACR.singleFactor] }, NOW)).toEqual({ ok: true });
	});

	it("refuses a weaker class and reports what was asked", () => {
		const a = { acr: ACR.singleFactor, authTime: NOW };
		expect(evaluateAuthRequirement(a, { acr: ACR.mfa }, NOW)).toEqual({
			ok: false,
			reason: "acr",
			acr: [ACR.mfa],
		});
	});

	it("accepts the weakest of several listed classes (acr_values is a list of acceptable values)", () => {
		const a = { acr: ACR.mfa, authTime: NOW };
		const wanted = `${ACR.phishingResistant} ${ACR.mfa}`;
		expect(evaluateAuthRequirement(a, { acr: wanted }, NOW)).toEqual({ ok: true });
	});

	it("fails closed for an unknown acr and for an assertion without one", () => {
		expect(evaluateAuthRequirement({ acr: ACR.mfa }, { acr: "urn:other" }, NOW).ok).toBe(false);
		expect(evaluateAuthRequirement({ authTime: NOW }, { acr: ACR.singleFactor }, NOW).ok).toBe(
			false,
		);
		expect(evaluateAuthRequirement(null, { acr: ACR.singleFactor }, NOW).ok).toBe(false);
	});

	it("checks max_age against auth_time when only a token is available", () => {
		const fresh = { authTime: NOW - 30 };
		expect(evaluateAuthRequirement(fresh, { maxAge: 60 }, NOW)).toEqual({ ok: true });
		const stale = evaluateAuthRequirement(fresh, { maxAge: 10 }, NOW);
		expect(stale).toEqual({ ok: false, reason: "max_age", maxAge: 10 });
		expect(evaluateAuthRequirement({}, { maxAge: 60 }, NOW).ok).toBe(false);
	});

	it("does not let a fresh password make an old passkey look fresh", () => {
		const events = [ev("password", 5), ev("passkey", 3600)];
		const assertion = { ...resolveAuthContext(events, NOW) };
		// Overall class is phishing resistant and the newest event is 5 seconds old, but the
		// passkey itself is an hour old.
		expect(
			evaluateAuthRequirement(assertion, { acr: ACR.phishingResistant, maxAge: 300 }, NOW).ok,
		).toBe(false);
		// A single factor request is happy with the fresh password.
		expect(evaluateAuthRequirement(assertion, { acr: ACR.singleFactor, maxAge: 300 }, NOW).ok).toBe(
			true,
		);
	});

	it("accepts a fresh TOTP on top of an older password for a fresh multi factor request", () => {
		const assertion = resolveAuthContext([ev("password", 7200), ev("totp", 20)], NOW);
		const verdict = evaluateAuthRequirement(assertion, { acr: ACR.mfa, maxAge: 300 }, NOW);
		expect(verdict).toEqual({ ok: true });
	});

	it("does not accept a fresh password for a fresh multi factor request", () => {
		const assertion = resolveAuthContext([ev("password", 20), ev("totp", 7200)], NOW);
		expect(evaluateAuthRequirement(assertion, { acr: ACR.mfa, maxAge: 300 }, NOW).ok).toBe(false);
	});

	it("treats max_age 0 as always asking again", () => {
		const assertion = resolveAuthContext([ev("passkey", 1)], NOW);
		expect(evaluateAuthRequirement(assertion, { maxAge: 0 }, NOW).ok).toBe(false);
	});

	it("exposes the classes weakest first", () => {
		expect(ACR_ORDER[0]).toBe(ACR.none);
		expect(ACR_ORDER.at(-1)).toBe(ACR.phishingResistant);
	});
});

describe("buildStepUpChallenge", () => {
	it("builds the RFC 9470 challenge with quoted acr_values and max_age", () => {
		const header = buildStepUpChallenge("Bearer", {
			ok: false,
			reason: "acr",
			acr: [ACR.phishingResistant],
			maxAge: 300,
		});
		expect(header).toContain('Bearer error="insufficient_user_authentication"');
		expect(header).toContain(`acr_values="${ACR.phishingResistant}"`);
		expect(header).toContain('max_age="300"');
	});

	it("never lets a quote or a line break out of a parameter", () => {
		const header = buildStepUpChallenge(
			"DPoP",
			{ ok: false, reason: "acr", acr: ['a"b\r\nc'] },
			{ description: 'bad"\nvalue' },
		);
		expect(header.startsWith("DPoP ")).toBe(true);
		expect(header).not.toMatch(/[\r\n]/);
		expect(header.match(/"/g)?.length).toBe(6);
	});
});

describe("session manager auth tracking", () => {
	let db: Database;
	const SECRET = "a-test-secret-that-is-at-least-32-chars-long!!";

	beforeEach(async () => {
		db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		db.insert(schema.users)
			.values({
				id: "u1",
				email: "u1@example.com",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
	});

	it("records the methods named at creation and reports amr, acr and authTime", async () => {
		const sessions = createSessionManager({ secret: SECRET }, db);
		const { session } = await sessions.create("u1", undefined, { authMethods: ["password"] });
		expect(session.auth?.acr).toBe(ACR.singleFactor);
		expect(session.auth?.amr).toEqual(["pwd"]);
		expect(session.auth?.authTime).toBe(Math.floor(session.createdAt.getTime() / 1000));
	});

	it("rates a session created without methods as none", async () => {
		const sessions = createSessionManager({ secret: SECRET }, db);
		const { token } = await sessions.create("u1");
		const read = await sessions.validate(token);
		expect(read?.auth?.acr).toBe(ACR.none);
		expect(read?.auth?.amr).toEqual([]);
	});

	it("raises acr and authTime when recordAuth stores a TOTP proof, and keeps it on validate", async () => {
		let clock = 1_800_000_000_000;
		const sessions = createSessionManager({ secret: SECRET, now: () => clock }, db);
		const { session, token } = await sessions.create("u1", undefined, {
			authMethods: ["password"],
		});
		clock += 3_600_000;
		const stepped = await sessions.recordAuth(session.id, "totp");
		expect(stepped?.auth?.acr).toBe(ACR.mfa);
		expect(stepped?.auth?.authTime).toBe(clock / 1000);
		const again = await sessions.validate(token);
		expect(again?.auth?.acr).toBe(ACR.mfa);
		expect(again?.auth?.amr).toEqual(["mfa", "otp", "pwd"]);
	});

	it("returns null for an unknown or expired session", async () => {
		const sessions = createSessionManager({ secret: SECRET }, db);
		expect(await sessions.recordAuth("missing", "totp")).toBeNull();
	});

	it("does not expose the stored events through session.metadata", async () => {
		const sessions = createSessionManager({ secret: SECRET }, db);
		const { session } = await sessions.create(
			"u1",
			{ device: "laptop" },
			{ authMethods: ["totp"] },
		);
		expect(session.metadata).toEqual({ device: "laptop" });
	});

	it("does not let caller metadata claim stored events on a fresh session", async () => {
		const sessions = createSessionManager({ secret: SECRET }, db);
		const forged = {
			theauthAuthEvents: [{ method: "passkey", at: Math.floor(Date.now() / 1000) }],
		};
		const { session } = await sessions.create("u1", forged, { authMethods: ["password"] });
		expect(session.auth?.acr).toBe(ACR.singleFactor);
		const bare = await sessions.create("u1", forged);
		expect(bare.session.auth?.acr).toBe(ACR.none);
	});

	it("ignores authMethods named inside caller metadata under other keys", async () => {
		const sessions = createSessionManager({ secret: SECRET }, db);
		const { session } = await sessions.create("u1", { authMethods: ["passkey"], amr: ["mfa"] });
		expect(session.auth?.acr).toBe(ACR.none);
	});

	it("keeps the stored events when the session is refreshed", async () => {
		let clock = 1_800_000_000_000;
		const mgr = createCookieSessionManager({ secret: SECRET, now: () => clock }, db);
		const first = await mgr.createSession("u1", undefined, { authMethods: ["password", "totp"] });
		clock += 3_600_000;
		const refreshed = await mgr.refreshSession(first.session.id);
		expect(refreshed).not.toBeNull();
		expect(refreshed?.session.id).not.toBe(first.session.id);
		// Refreshing is not a new login: acr and authTime come from the original proofs.
		expect(refreshed?.session.auth?.acr).toBe(ACR.mfa);
		expect(refreshed?.session.auth?.authTime).toBe(first.session.auth?.authTime);
	});
});
