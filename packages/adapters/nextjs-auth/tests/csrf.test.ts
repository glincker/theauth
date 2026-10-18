import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "../src/config.js";

vi.mock("server-only", () => ({}));

const jar = new Map<string, string>();
const store = {
	get: vi.fn((name: string) => {
		const value = jar.get(name);
		return value === undefined ? undefined : { name, value };
	}),
	set: vi.fn((name: string, value: string) => {
		jar.set(name, value);
	}),
};
vi.mock("next/headers", () => ({
	cookies: vi.fn(async () => store),
	headers: vi.fn(async () => new Headers()),
}));

const { createCsrfToken, verifyCsrfToken } = await import("../src/csrf.js");
const { verifyCsrfRequest } = await import("../src/csrf-verify.js");
const { createSignOutHandler, createSignOutRouteHandler } = await import(
	"../src/route-handlers.js"
);

const SECRET = "test-secret-test-secret-test-secret-0123456789";
const OTHER = "other-secret-other-secret-other-secret-9876";
const config = createAuthConfig({
	backendUrl: "https://api.example.com",
	appUrl: "https://example.com",
	secret: SECRET,
	isProd: false,
});

describe("signed CSRF token", () => {
	it("verifies for the session it was issued for", async () => {
		const t = await createCsrfToken(SECRET, "session-a");
		expect(await verifyCsrfToken(SECRET, "session-a", t)).toBe(true);
	});
	it("rejects a replay across sessions", async () => {
		const t = await createCsrfToken(SECRET, "session-a");
		expect(await verifyCsrfToken(SECRET, "session-b", t)).toBe(false);
	});
	it("rejects forged tokens (random, unsigned, wrong secret, tampered)", async () => {
		expect(await verifyCsrfToken(SECRET, "session-a", "a".repeat(64))).toBe(false);
		expect(await verifyCsrfToken(SECRET, "session-a", "")).toBe(false);
		const foreign = await createCsrfToken(OTHER, "session-a");
		expect(await verifyCsrfToken(SECRET, "session-a", foreign)).toBe(false);
		const t = await createCsrfToken(SECRET, "session-a");
		expect(await verifyCsrfToken(SECRET, "session-a", `${t.slice(0, -2)}AA`)).toBe(false);
	});
});

describe("verifyCsrfRequest (double submit)", () => {
	beforeEach(() => {
		jar.clear();
	});

	async function login(session: string): Promise<string> {
		const t = await createCsrfToken(SECRET, session);
		jar.set("glinr-token", session);
		jar.set("glinr-csrf", t);
		return t;
	}

	it("accepts matching header and cookie bound to the session", async () => {
		const t = await login("s1");
		expect(await verifyCsrfRequest(config, t)).toBe(true);
	});
	it("rejects a missing header or missing cookie", async () => {
		const t = await login("s1");
		expect(await verifyCsrfRequest(config, null)).toBe(false);
		jar.delete("glinr-csrf");
		expect(await verifyCsrfRequest(config, t)).toBe(false);
	});
	it("rejects a header that differs from the cookie", async () => {
		await login("s1");
		const other = await createCsrfToken(SECRET, "s1");
		expect(await verifyCsrfRequest(config, other)).toBe(false);
	});
	it("rejects an attacker-chosen matching pair (cookie injection)", async () => {
		jar.set("glinr-token", "s1");
		jar.set("glinr-csrf", "attacker-value");
		expect(await verifyCsrfRequest(config, "attacker-value")).toBe(false);
	});
	it("rejects a token replayed from another session", async () => {
		const old = await createCsrfToken(SECRET, "s-old");
		jar.set("glinr-token", "s-new");
		jar.set("glinr-csrf", old);
		expect(await verifyCsrfRequest(config, old)).toBe(false);
	});
});

describe("state changing handlers enforce CSRF", () => {
	beforeEach(() => {
		jar.clear();
		vi.restoreAllMocks();
		vi.spyOn(global, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
	});

	it("route handler returns 403 without a valid token and does not clear cookies", async () => {
		jar.set("glinr-token", "s1");
		const handler = createSignOutRouteHandler(config);
		const res = await handler(new Request("https://example.com/signout", { method: "POST" }));
		expect(res.status).toBe(403);
		expect(jar.get("glinr-token")).toBe("s1");
	});
	it("route handler signs out with a valid token", async () => {
		const t = await createCsrfToken(SECRET, "s1");
		jar.set("glinr-token", "s1");
		jar.set("glinr-csrf", t);
		const handler = createSignOutRouteHandler(config);
		const res = await handler(
			new Request("https://example.com/signout", {
				method: "POST",
				headers: { "x-csrf-token": t },
			}),
		);
		expect(res.status).toBe(200);
		expect(jar.get("glinr-token")).toBe("");
	});
	it("server action form refuses a missing or forged token", async () => {
		jar.set("glinr-token", "s1");
		const signOut = createSignOutHandler(config);
		expect((await signOut()).success).toBe(false);
		expect((await signOut("forged")).success).toBe(false);
		expect(jar.get("glinr-token")).toBe("s1");
		const t = await createCsrfToken(SECRET, "s1");
		jar.set("glinr-csrf", t);
		expect((await signOut(t)).success).toBe(true);
	});
});
