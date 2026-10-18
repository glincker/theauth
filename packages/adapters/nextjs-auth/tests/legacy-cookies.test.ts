import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "../src/config.js";

vi.mock("server-only", () => ({}));

const jar = new Map<string, string>();
const store = {
	get: vi.fn((name: string) => {
		const value = jar.get(name);
		return value === undefined ? undefined : { name, value };
	}),
	set: vi.fn(),
};
vi.mock("next/headers", () => ({
	cookies: vi.fn(async () => store),
	headers: vi.fn(async () => new Headers()),
}));

const { getSessionToken } = await import("../src/cookies.js");

const base = {
	backendUrl: "https://api.example.com",
	appUrl: "https://example.com",
	secret: "test-secret-test-secret-test-secret-0123456789",
};

describe("plain-name cookie shadowing", () => {
	beforeEach(() => jar.clear());

	it("ignores the plain cookie when __Host- is in use, even when __Host- is absent", async () => {
		const config = createAuthConfig({ ...base, isProd: true });
		jar.set("glinr-token", "injected");
		expect(await getSessionToken(config)).toBe("");
	});
	it("prefers __Host- over the plain cookie", async () => {
		const config = createAuthConfig({ ...base, isProd: true });
		jar.set("glinr-token", "injected");
		jar.set("__Host-glinr-token", "real");
		expect(await getSessionToken(config)).toBe("real");
	});
	it("accepts plain only with legacyCookieNames and only when __Host- is absent", async () => {
		const config = createAuthConfig({ ...base, isProd: true, legacyCookieNames: true });
		jar.set("glinr-token", "old");
		expect(await getSessionToken(config)).toBe("old");
		jar.set("__Host-glinr-token", "real");
		expect(await getSessionToken(config)).toBe("real");
	});
	it("defaults legacyCookieNames to false", () => {
		expect(createAuthConfig({ ...base }).legacyCookieNames).toBe(false);
	});
	it("does not read a __Host- cookie in plain-name (dev) mode unless legacy", async () => {
		const config = createAuthConfig({ ...base, isProd: false, secure: false });
		jar.set("__Host-glinr-token", "x");
		expect(await getSessionToken(config)).toBe("");
	});
});
