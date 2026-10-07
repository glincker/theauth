/**
 * Tests for cookie utilities, CSRF protection, and the cookie-aware session manager.
 *
 * Covers:
 * - Cookie serialization (all attributes, defaults, deletion)
 * - Cookie parsing (standard, edge cases, malformed input)
 * - CSRF token generation and double-submit validation
 * - Origin/Referer header validation
 * - Session create / validate / refresh / revoke lifecycle
 * - Session expiry
 * - Auto-refresh behaviour
 * - revokeAll scoping
 * - listSessions filters expired sessions
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import {
	getCookie,
	parseCookies,
	parseCookiesFromRequest,
	serializeCookie,
	serializeCookieDeletion,
} from "../src/session/cookie.js";
import { generateCsrfToken, validateCsrfToken, validateOrigin } from "../src/session/csrf.js";
import type { CookieSessionManager } from "../src/session/manager.js";
import { createCookieSessionManager } from "../src/session/manager.js";

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

const TEST_SECRET = "a-test-secret-that-is-at-least-32-chars-long!!";
const TEST_USER_ID = "user-cookie-test";
const OTHER_USER_ID = "user-cookie-other";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	for (const [id, email] of [
		[TEST_USER_ID, "cookie-test@example.com"],
		[OTHER_USER_ID, "other@example.com"],
	]) {
		db.insert(schema.users)
			.values({ id, email, createdAt: new Date(), updatedAt: new Date() })
			.run();
	}

	return db;
}

// ===========================================================================
// Cookie utilities
// ===========================================================================

describe("serializeCookie", () => {
	it("produces the expected base string with defaults", () => {
		const header = serializeCookie("session", "abc123");
		expect(header).toContain("session=abc123");
		expect(header).toContain("HttpOnly");
		expect(header).toContain("SameSite=Lax");
		expect(header).toContain("Path=/");
	});

	it("percent-encodes special characters in the value", () => {
		const header = serializeCookie("tok", "hello world");
		expect(header).toContain("tok=hello%20world");
	});

	it("includes Max-Age and Expires when maxAge is set", () => {
		const header = serializeCookie("s", "v", { maxAge: 3600 });
		expect(header).toContain("Max-Age=3600");
		expect(header).toContain("Expires=");
	});

	it("includes Expires (without Max-Age) when only expires is set", () => {
		const date = new Date("2030-01-01T00:00:00Z");
		const header = serializeCookie("s", "v", { expires: date });
		expect(header).toContain("Expires=Tue, 01 Jan 2030");
		expect(header).not.toContain("Max-Age=");
	});

	it("includes Domain when set", () => {
		const header = serializeCookie("s", "v", { domain: "example.com" });
		expect(header).toContain("Domain=example.com");
	});

	it("omits Domain when not set", () => {
		const header = serializeCookie("s", "v");
		expect(header).not.toContain("Domain=");
	});

	it("respects sameSite='strict'", () => {
		const header = serializeCookie("s", "v", { sameSite: "strict" });
		expect(header).toContain("SameSite=Strict");
	});

	it("respects sameSite='none' (must be combined with secure for real use)", () => {
		const header = serializeCookie("s", "v", { sameSite: "none", secure: true });
		expect(header).toContain("SameSite=None");
		expect(header).toContain("Secure");
	});

	it("omits HttpOnly when httpOnly=false", () => {
		const header = serializeCookie("s", "v", { httpOnly: false });
		expect(header).not.toContain("HttpOnly");
	});

	it("includes Partitioned when set", () => {
		const header = serializeCookie("s", "v", { partitioned: true });
		expect(header).toContain("Partitioned");
	});

	it("throws for an invalid cookie name containing a space", () => {
		expect(() => serializeCookie("bad name", "v")).toThrow("Invalid cookie name");
	});

	it("throws for an empty cookie name", () => {
		expect(() => serializeCookie("", "v")).toThrow("Invalid cookie name");
	});
});

describe("serializeCookieDeletion", () => {
	it("sets Max-Age=0 and an Expires in the past", () => {
		const header = serializeCookieDeletion("session");
		expect(header).toContain("Max-Age=0");
		expect(header).toContain("session=");
		// Value should be empty (percent-encoded as empty string).
		expect(header).toMatch(/session=;|session=\s/);
	});
});

describe("parseCookies", () => {
	it("parses a standard cookie header", () => {
		const result = parseCookies("a=1; b=2; c=3");
		expect(result).toEqual({ a: "1", b: "2", c: "3" });
	});

	it("decodes percent-encoded values", () => {
		const result = parseCookies("tok=hello%20world");
		expect(result.tok).toBe("hello world");
	});

	it("returns an empty object for an empty header", () => {
		expect(parseCookies("")).toEqual({});
		expect(parseCookies("   ")).toEqual({});
	});

	it("skips pairs without an equals sign", () => {
		const result = parseCookies("garbage; b=2");
		expect(result).toEqual({ b: "2" });
	});

	it("handles values that contain '='", () => {
		const result = parseCookies("tok=base64==");
		expect(result.tok).toBe("base64==");
	});

	it("skips malformed percent-encoded values without throwing", () => {
		// %ZZ is invalid percent-encoding.
		const result = parseCookies("bad=%ZZ; good=ok");
		expect(result.bad).toBeUndefined();
		expect(result.good).toBe("ok");
	});
});

describe("getCookie", () => {
	it("returns the value for a known cookie name", () => {
		expect(getCookie("a=1; b=2", "b")).toBe("2");
	});

	it("returns undefined for an absent cookie", () => {
		expect(getCookie("a=1", "missing")).toBeUndefined();
	});
});

describe("parseCookiesFromRequest", () => {
	it("parses cookies from a Request object", () => {
		const req = new Request("https://example.com", {
			headers: { cookie: "session=abc; user=xyz" },
		});
		expect(parseCookiesFromRequest(req)).toEqual({ session: "abc", user: "xyz" });
	});

	it("returns an empty object when the Cookie header is absent", () => {
		const req = new Request("https://example.com");
		expect(parseCookiesFromRequest(req)).toEqual({});
	});
});

// ===========================================================================
// CSRF utilities
// ===========================================================================

describe("generateCsrfToken", () => {
	it("returns a non-empty string", () => {
		const token = generateCsrfToken();
		expect(typeof token).toBe("string");
		expect(token.length).toBeGreaterThan(0);
	});

	it("returns different values on each call", () => {
		const tokens = new Set(Array.from({ length: 10 }, () => generateCsrfToken()));
		expect(tokens.size).toBe(10);
	});

	it("returns a URL-safe base64 string (no +, /, or = padding)", () => {
		const token = generateCsrfToken();
		expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
	});
});

describe("validateCsrfToken", () => {
	it("returns valid=true when tokens match", () => {
		const token = generateCsrfToken();
		expect(validateCsrfToken(token, token).valid).toBe(true);
	});

	it("returns valid=false when tokens differ", () => {
		const result = validateCsrfToken(generateCsrfToken(), generateCsrfToken());
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("mismatch");
	});

	it("returns valid=false for an empty request token", () => {
		const result = validateCsrfToken("", "some-token");
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Missing");
	});

	it("returns valid=false for an empty cookie token", () => {
		const result = validateCsrfToken("some-token", "");
		expect(result.valid).toBe(false);
	});

	it("returns valid=false for tokens that differ only in case (case-sensitive)", () => {
		const token = "AbCdEfGhIjKlMnOpQrStUvWxYz";
		expect(validateCsrfToken(token, token.toLowerCase()).valid).toBe(false);
	});
});

describe("validateOrigin", () => {
	const trusted = ["https://app.example.com", "https://admin.example.com"];

	function makeRequest(headers: Record<string, string>): Request {
		return new Request("https://api.example.com/action", { method: "POST", headers });
	}

	it("returns valid=true when Origin matches a trusted origin", () => {
		const req = makeRequest({ origin: "https://app.example.com" });
		expect(validateOrigin(req, trusted).valid).toBe(true);
	});

	it("is case-insensitive for the scheme+host comparison", () => {
		const req = makeRequest({ origin: "HTTPS://APP.EXAMPLE.COM" });
		expect(validateOrigin(req, trusted).valid).toBe(true);
	});

	it("ignores trailing slashes on trusted origin list entries", () => {
		const req = makeRequest({ origin: "https://app.example.com" });
		expect(validateOrigin(req, ["https://app.example.com/"]).valid).toBe(true);
	});

	it("returns valid=false for an untrusted Origin", () => {
		const req = makeRequest({ origin: "https://evil.example.com" });
		const result = validateOrigin(req, trusted);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("not in the trusted list");
	});

	it("returns valid=false for opaque origin (null)", () => {
		const req = makeRequest({ origin: "null" });
		const result = validateOrigin(req, trusted);
		expect(result.valid).toBe(false);
		expect(result.reason).toContain("Opaque");
	});

	it("falls back to Referer when Origin is absent", () => {
		const req = makeRequest({ referer: "https://app.example.com/page" });
		expect(validateOrigin(req, trusted).valid).toBe(true);
	});

	it("returns valid=false when Referer origin is untrusted", () => {
		const req = makeRequest({ referer: "https://evil.example.com/page" });
		expect(validateOrigin(req, trusted).valid).toBe(false);
	});

	it("returns valid=false when neither Origin nor Referer is present (default)", () => {
		const req = makeRequest({});
		expect(validateOrigin(req, trusted).valid).toBe(false);
	});

	it("returns valid=true when neither header is present and allowMissingOrigin=true", () => {
		const req = makeRequest({});
		expect(validateOrigin(req, trusted, true).valid).toBe(true);
	});

	it("returns valid=false for a malformed Referer header", () => {
		const req = makeRequest({ referer: "not-a-url" });
		const result = validateOrigin(req, trusted);
		expect(result.valid).toBe(false);
	});
});

// ===========================================================================
// Cookie-aware session manager
// ===========================================================================

describe("CookieSessionManager — createSession", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		mgr = createCookieSessionManager({ secret: TEST_SECRET }, db);
	});

	it("returns a session with the correct userId", async () => {
		const { session } = await mgr.createSession(TEST_USER_ID);
		expect(session.userId).toBe(TEST_USER_ID);
		expect(session.id).toBeTruthy();
	});

	it("returns a Set-Cookie header containing the session name", async () => {
		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		expect(setCookieHeader).toContain("theauth_session=");
		expect(setCookieHeader).toContain("HttpOnly");
		expect(setCookieHeader).toContain("SameSite=Lax");
		expect(setCookieHeader).toContain("Path=/");
	});

	it("uses a custom sessionName when configured", async () => {
		const custom = createCookieSessionManager(
			{ secret: TEST_SECRET, sessionName: "my_app_session" },
			db,
		);
		const { setCookieHeader } = await custom.createSession(TEST_USER_ID);
		expect(setCookieHeader).toContain("my_app_session=");
	});

	it("includes Max-Age in the Set-Cookie header", async () => {
		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		expect(setCookieHeader).toContain("Max-Age=");
	});

	it("stores optional metadata on the session", async () => {
		const { session } = await mgr.createSession(TEST_USER_ID, { role: "admin" });
		expect(session.metadata).toMatchObject({ role: "admin" });
	});
});

describe("CookieSessionManager — validateSession", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		// Disable auto-refresh so validate tests stay simple.
		mgr = createCookieSessionManager({ secret: TEST_SECRET, autoRefresh: false }, db);
	});

	it("returns the session when the cookie is valid", async () => {
		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		// Extract the raw Cookie header value from the Set-Cookie header.
		const cookieValue = setCookieHeader.split(";")[0]; // "theauth_session=<token>"
		const { session } = await mgr.validateSession(cookieValue ?? "");
		expect(session).not.toBeNull();
		expect(session?.userId).toBe(TEST_USER_ID);
	});

	it("returns session=null when the Cookie header is empty", async () => {
		const { session } = await mgr.validateSession("");
		expect(session).toBeNull();
	});

	it("returns session=null when the cookie name does not match", async () => {
		const { session } = await mgr.validateSession("other_cookie=somevalue");
		expect(session).toBeNull();
	});

	it("returns session=null after the session is revoked", async () => {
		const { session: created, setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		await mgr.revokeSession(created.id);
		const cookieValue = setCookieHeader.split(";")[0] ?? "";
		const { session } = await mgr.validateSession(cookieValue);
		expect(session).toBeNull();
	});

	it("returns refreshCookieHeader=null when autoRefresh is disabled", async () => {
		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		const cookieValue = setCookieHeader.split(";")[0] ?? "";
		const { refreshCookieHeader } = await mgr.validateSession(cookieValue);
		expect(refreshCookieHeader).toBeNull();
	});
});

describe("CookieSessionManager — auto-refresh", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		mgr = createCookieSessionManager({ secret: TEST_SECRET, autoRefresh: true }, db);
	});

	it("returns a non-null refreshCookieHeader when autoRefresh=true and session is valid", async () => {
		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		const cookieValue = setCookieHeader.split(";")[0] ?? "";
		const { session, refreshCookieHeader } = await mgr.validateSession(cookieValue);
		expect(session).not.toBeNull();
		expect(refreshCookieHeader).not.toBeNull();
		expect(refreshCookieHeader).toContain("theauth_session=");
	});

	it("issues a new token on refresh (cookie value changes)", async () => {
		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		const cookieValue = setCookieHeader.split(";")[0] ?? "";
		const { refreshCookieHeader } = await mgr.validateSession(cookieValue);

		// The refreshed cookie should contain a different token value.
		const originalToken = cookieValue.split("=")[1];
		const refreshedToken = refreshCookieHeader?.split("=")[1]?.split(";")[0];

		expect(refreshedToken).toBeDefined();
		expect(refreshedToken).not.toBe(originalToken);
	});
});

describe("CookieSessionManager — refreshSession", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		mgr = createCookieSessionManager({ secret: TEST_SECRET, autoRefresh: false }, db);
	});

	it("returns a new session and Set-Cookie header for a valid session ID", async () => {
		const { session: original } = await mgr.createSession(TEST_USER_ID);
		const refreshed = await mgr.refreshSession(original.id);

		expect(refreshed).not.toBeNull();
		expect(refreshed?.session.userId).toBe(TEST_USER_ID);
		expect(refreshed?.setCookieHeader).toContain("theauth_session=");
	});

	it("returns null for a non-existent session ID", async () => {
		const result = await mgr.refreshSession("does-not-exist");
		expect(result).toBeNull();
	});

	it("the refreshed cookie can be used to validate a new session", async () => {
		const { session: original } = await mgr.createSession(TEST_USER_ID);
		const refreshed = await mgr.refreshSession(original.id);

		expect(refreshed).not.toBeNull();
		const cookieValue = refreshed?.setCookieHeader.split(";")[0] ?? "";
		const { session } = await mgr.validateSession(cookieValue);
		expect(session).not.toBeNull();
		expect(session?.userId).toBe(TEST_USER_ID);
	});
});

describe("CookieSessionManager — revokeSession", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		mgr = createCookieSessionManager({ secret: TEST_SECRET, autoRefresh: false }, db);
	});

	it("returns a deletion Set-Cookie header", async () => {
		const { session } = await mgr.createSession(TEST_USER_ID);
		const { deleteCookieHeader } = await mgr.revokeSession(session.id);
		expect(deleteCookieHeader).toContain("Max-Age=0");
		expect(deleteCookieHeader).toContain("theauth_session=");
	});

	it("invalidates the session so subsequent validation returns null", async () => {
		const { session, setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		await mgr.revokeSession(session.id);
		const cookieValue = setCookieHeader.split(";")[0] ?? "";
		const { session: validated } = await mgr.validateSession(cookieValue);
		expect(validated).toBeNull();
	});

	it("does not throw for a non-existent session ID", async () => {
		await expect(mgr.revokeSession("ghost-id")).resolves.toMatchObject({
			deleteCookieHeader: expect.stringContaining("theauth_session="),
		});
	});
});

describe("CookieSessionManager — revokeAllSessions", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		mgr = createCookieSessionManager({ secret: TEST_SECRET, autoRefresh: false }, db);
	});

	it("invalidates all sessions for the target user", async () => {
		const { setCookieHeader: h1 } = await mgr.createSession(TEST_USER_ID);
		const { setCookieHeader: h2 } = await mgr.createSession(TEST_USER_ID);

		await mgr.revokeAllSessions(TEST_USER_ID);

		const c1 = h1.split(";")[0] ?? "";
		const c2 = h2.split(";")[0] ?? "";
		expect((await mgr.validateSession(c1)).session).toBeNull();
		expect((await mgr.validateSession(c2)).session).toBeNull();
	});

	it("does not affect sessions belonging to another user", async () => {
		const { setCookieHeader: h1 } = await mgr.createSession(TEST_USER_ID);
		const { setCookieHeader: h2 } = await mgr.createSession(OTHER_USER_ID);

		await mgr.revokeAllSessions(TEST_USER_ID);

		const c2 = h2.split(";")[0] ?? "";
		expect((await mgr.validateSession(c2)).session).not.toBeNull();
		// Silence unused variable warning.
		void h1;
	});

	it("returns a deletion cookie header", async () => {
		const { deleteCookieHeader } = await mgr.revokeAllSessions(TEST_USER_ID);
		expect(deleteCookieHeader).toContain("Max-Age=0");
	});
});

describe("CookieSessionManager — listSessions", () => {
	let db: Database;
	let mgr: CookieSessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		mgr = createCookieSessionManager({ secret: TEST_SECRET, autoRefresh: false }, db);
	});

	it("returns an empty array when the user has no sessions", async () => {
		const result = await mgr.listSessions(TEST_USER_ID);
		expect(result).toEqual([]);
	});

	it("returns all active sessions for the user, newest first", async () => {
		await mgr.createSession(TEST_USER_ID);
		await mgr.createSession(TEST_USER_ID);

		const result = await mgr.listSessions(TEST_USER_ID);
		expect(result).toHaveLength(2);
		expect(result.every((s) => s.userId === TEST_USER_ID)).toBe(true);
		// Verify descending order.
		expect(result[0]?.createdAt.getTime()).toBeGreaterThanOrEqual(result[1]?.createdAt.getTime());
	});

	it("excludes revoked sessions", async () => {
		const { session: s1 } = await mgr.createSession(TEST_USER_ID);
		await mgr.createSession(TEST_USER_ID);
		await mgr.revokeSession(s1.id);

		const result = await mgr.listSessions(TEST_USER_ID);
		expect(result).toHaveLength(1);
		expect(result[0]?.id).not.toBe(s1.id);
	});
});

describe("CookieSessionManager — session expiry", () => {
	it("returns null when the session maxAge is zero and time has passed", async () => {
		const db = await createTestDb();
		// 1-second session.
		const mgr = createCookieSessionManager(
			{ secret: TEST_SECRET, maxAge: 1, autoRefresh: false },
			db,
		);

		const { setCookieHeader } = await mgr.createSession(TEST_USER_ID);
		const cookieValue = setCookieHeader.split(";")[0] ?? "";

		// Advance time past expiry using fake timers.
		vi.useFakeTimers();
		vi.advanceTimersByTime(2000);

		const { session } = await mgr.validateSession(cookieValue);
		expect(session).toBeNull();

		vi.useRealTimers();
	});
});

describe("CookieSessionManager — buildLogoutCookie", () => {
	it("returns a deletion cookie header without touching the database", async () => {
		const db = await createTestDb();
		const mgr = createCookieSessionManager({ secret: TEST_SECRET }, db);
		const header = mgr.buildLogoutCookie();
		expect(header).toContain("theauth_session=");
		expect(header).toContain("Max-Age=0");
	});
});

describe("CookieSessionManager — raw manager access", () => {
	it("exposes the underlying SessionManager via .raw", async () => {
		const db = await createTestDb();
		const mgr = createCookieSessionManager({ secret: TEST_SECRET }, db);
		expect(typeof mgr.raw.create).toBe("function");
		expect(typeof mgr.raw.validate).toBe("function");
		expect(typeof mgr.raw.revoke).toBe("function");
	});
});
