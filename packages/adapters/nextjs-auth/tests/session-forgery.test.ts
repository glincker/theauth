import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "../src/config.js";

// Regression tests for the unsigned session cache cookie forgery (0.2.0).
vi.mock("server-only", () => ({}));

const jar = new Map<string, string>();
const mockCookieStore = {
	get: vi.fn((name: string) => {
		const value = jar.get(name);
		return value === undefined ? undefined : { name, value };
	}),
	set: vi.fn((name: string, value: string) => {
		jar.set(name, value);
	}),
	delete: vi.fn((name: string) => {
		jar.delete(name);
	}),
};

vi.mock("next/headers", () => ({
	cookies: vi.fn(async () => mockCookieStore),
	headers: vi.fn(async () => new Headers()),
}));

const { writeSessionCache } = await import("../src/cookies.js");
const { getServerSession } = await import("../src/server-session.js");

const SECRET = "test-secret-test-secret-test-secret-0123456789";

const config = createAuthConfig({
	backendUrl: "https://api.example.com",
	appUrl: "https://example.com",
	secret: SECRET,
	cookies: { sessionPrefix: "glinr" },
});

function backendMe(user: Record<string, unknown>): Response {
	return new Response(JSON.stringify(user), {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});
}

describe("session cache forgery", () => {
	let fetchMock: MockInstance;

	beforeEach(() => {
		jar.clear();
		vi.clearAllMocks();
		fetchMock = vi.spyOn(global, "fetch");
	});

	const forged = JSON.stringify({
		user: { id: "victim", role: "admin" },
		expiresAt: null,
		stampedAt: Date.now(),
	});

	it("does not accept a hand-written JSON cache cookie with no session token", async () => {
		jar.set(config.cookies.cacheName, forged);
		const session = await getServerSession(config);
		expect(session).toBeNull();
	});

	it("does not accept a forged cache cookie alongside a real token, and asks the backend", async () => {
		jar.set("glinr-token", "real-token-of-an-ordinary-user");
		jar.set("__Host-glinr-token", "real-token-of-an-ordinary-user");
		jar.set(config.cookies.cacheName, forged);
		fetchMock.mockResolvedValueOnce(backendMe({ id: "ordinary", role: "user" }));

		const session = await getServerSession(config);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(session?.user).toEqual({ id: "ordinary", role: "user" });
	});

	async function issueSignedCache(token: string, user: Record<string, unknown>): Promise<string> {
		jar.set("glinr-token", token);
		jar.set("__Host-glinr-token", token);
		await writeSessionCache(config, { user, expiresAt: null, stampedAt: Date.now() }, token);
		const value = jar.get(config.cookies.cacheName);
		if (!value) throw new Error("cache cookie was not written");
		return value;
	}

	it("serves a genuine signed cache entry without calling the backend", async () => {
		await issueSignedCache("tok-1", { id: "u1", role: "user" });
		const session = await getServerSession(config);
		expect(fetchMock).not.toHaveBeenCalled();
		expect(session?.user).toEqual({ id: "u1", role: "user" });
	});

	it("rejects a signed cache whose payload was edited", async () => {
		const value = await issueSignedCache("tok-1", { id: "u1", role: "user" });
		const [v, , mac] = value.split(".");
		const evil = btoa(
			JSON.stringify({
				v: 1,
				u: { id: "u1", role: "admin" },
				e: null,
				s: Date.now(),
				x: Date.now() + 1e6,
				t: "x",
			}),
		);
		jar.set(config.cookies.cacheName, `${v}.${evil}.${mac}`);
		fetchMock.mockResolvedValueOnce(backendMe({ id: "u1", role: "user" }));
		const session = await getServerSession(config);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(session?.user).toEqual({ id: "u1", role: "user" });
	});

	it("rejects a signed cache replayed with a different session token", async () => {
		const value = await issueSignedCache("tok-victim", { id: "victim", role: "admin" });
		jar.set("glinr-token", "tok-attacker");
		jar.set("__Host-glinr-token", "tok-attacker");
		jar.set(config.cookies.cacheName, value);
		fetchMock.mockResolvedValueOnce(backendMe({ id: "attacker", role: "user" }));
		const session = await getServerSession(config);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(session?.user).toEqual({ id: "attacker", role: "user" });
	});

	it("rejects a cache signed with a different secret", async () => {
		const other = createAuthConfig({
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			secret: "another-secret-another-secret-another-secret!",
		});
		jar.set("glinr-token", "tok-1");
		jar.set("__Host-glinr-token", "tok-1");
		await writeSessionCache(
			other,
			{ user: { id: "x", role: "admin" }, expiresAt: null, stampedAt: Date.now() },
			"tok-1",
		);
		fetchMock.mockResolvedValueOnce(backendMe({ id: "u1" }));
		const session = await getServerSession(config);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(session?.user).toEqual({ id: "u1" });
	});

	it("rejects an expired cache entry", async () => {
		await issueSignedCache("tok-1", { id: "u1" });
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(Date.now() + config.cookieCacheMaxAgeMs + 1000);
		try {
			fetchMock.mockResolvedValueOnce(backendMe({ id: "u1" }));
			await getServerSession(config);
			expect(fetchMock).toHaveBeenCalledTimes(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("writes the cache cookie HttpOnly, Secure, Lax, Path=/ and no longer than the session", async () => {
		jar.set("glinr-token", "tok-1");
		const soon = new Date(Date.now() + 90_000).toISOString();
		await writeSessionCache(
			config,
			{ user: { id: "u" }, expiresAt: soon, stampedAt: Date.now() },
			"tok-1",
		);
		const call = mockCookieStore.set.mock.calls.find((c) => c[0] === config.cookies.cacheName);
		const opts = call?.[2] as {
			httpOnly: boolean;
			secure: boolean;
			sameSite: string;
			path: string;
			maxAge: number;
		};
		expect(opts).toMatchObject({ httpOnly: true, secure: true, sameSite: "lax", path: "/" });
		expect(opts.maxAge).toBeLessThanOrEqual(90);
		expect(opts.maxAge).toBeGreaterThan(0);
	});

	it("does not write an oversized cache cookie", async () => {
		jar.set("glinr-token", "tok-1");
		await writeSessionCache(
			config,
			{ user: { id: "u", blob: "x".repeat(5000) }, expiresAt: null, stampedAt: Date.now() },
			"tok-1",
		);
		expect(mockCookieStore.set).not.toHaveBeenCalled();
	});
});
