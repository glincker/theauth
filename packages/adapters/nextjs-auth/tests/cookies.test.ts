import { describe, expect, it } from "vitest";
import { createAuthConfig } from "../src/config.js";

const TEST_SECRET = "test-secret-test-secret-test-secret-0123456789";

// Tests cookie name derivation and config resolution. next/headers and NextResponse are mocked out.

describe("createAuthConfig: cookie name resolution", () => {
	it("uses __Host- prefix when isProd=true", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: true,
		});
		expect(config.cookies.sessionName).toBe("__Host-glinr-token");
		expect(config.cookies.csrfName).toBe("__Host-glinr-csrf");
	});

	it("uses plain prefix when isProd=false", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "http://localhost:9100",
			appUrl: "http://localhost:3000",
			isProd: false,
		});
		expect(config.cookies.sessionName).toBe("glinr-token");
		expect(config.cookies.csrfName).toBe("glinr-csrf");
	});

	it("uses custom sessionPrefix for cookie names", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: true,
			cookies: { sessionPrefix: "myapp" },
		});
		expect(config.cookies.sessionName).toBe("__Host-myapp-token");
		expect(config.cookies.csrfName).toBe("__Host-myapp-csrf");
		expect(config.cookies.refresh).toBe("__Host-myapp-refresh-token");
		expect(config.cookies.cacheName).toBe("__Host-myapp-session-cache");
	});

	it("uses the __Host- refresh cookie by default, even outside production", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: false,
		});
		expect(config.cookies.refresh).toBe("__Host-glinr-refresh-token");
	});

	it("drops the __Host- refresh prefix only when secure is false (plain http localhost)", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "http://localhost:3001",
			appUrl: "http://localhost:3000",
			secure: false,
		});
		expect(config.cookies.refresh).toBe("glinr-refresh-token");
	});

	it("allows custom refresh cookie name override", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: false,
			cookies: { refresh: "my-custom-refresh" },
		});
		expect(config.cookies.refresh).toBe("my-custom-refresh");
	});

	it("strips trailing slashes from backendUrl and appUrl", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com/",
			appUrl: "https://example.com/",
			isProd: true,
		});
		expect(config.backendUrl).toBe("https://api.example.com");
		expect(config.appUrl).toBe("https://example.com");
	});

	it("applies default endpoint paths", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		expect(config.endpoints.me).toBe("/api/auth/me");
		expect(config.endpoints.refresh).toBe("/api/auth/refresh");
		expect(config.endpoints.signOut).toBe("/api/auth/logout");
	});

	it("respects endpoint overrides", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			endpoints: {
				me: "/api/v1/auth/me",
				refresh: "/api/auth/token/refresh",
				signOut: "/api/v1/auth/logout",
			},
		});
		expect(config.endpoints.me).toBe("/api/v1/auth/me");
		expect(config.endpoints.refresh).toBe("/api/auth/token/refresh");
		expect(config.endpoints.signOut).toBe("/api/v1/auth/logout");
	});

	it("applies default cookieCacheMaxAgeMs of 5 minutes", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		expect(config.cookieCacheMaxAgeMs).toBe(5 * 60 * 1000);
	});

	it("applies default expiryRefreshBufferS of 60", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		expect(config.expiryRefreshBufferS).toBe(60);
	});

	it("passes through mapUser when provided", () => {
		const mapUser = (raw: unknown) => ({
			id: "custom",
			name: String((raw as Record<string, unknown>).name ?? ""),
		});
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			mapUser,
		});
		expect(config.mapUser).toBe(mapUser);
	});

	it("uses default mapUser that returns raw as TUser when none provided", () => {
		const config = createAuthConfig({
			secret: TEST_SECRET,
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		const raw = { id: "123", email: "test@example.com" };
		expect(config.mapUser(raw)).toEqual(raw);
		expect(config.mapUser(null)).toBeNull();
	});
});

describe("createAuthConfig: secret and secure", () => {
	const base = { backendUrl: "https://api.example.com", appUrl: "https://example.com" };

	it("throws when the secret is missing", () => {
		// @ts-expect-error secret is required
		expect(() => createAuthConfig({ ...base })).toThrow(/secret/);
	});

	it("throws when the secret is shorter than 32 bytes", () => {
		expect(() => createAuthConfig({ ...base, secret: "short" })).toThrow(/32 bytes/);
		expect(() => createAuthConfig({ ...base, secret: "a".repeat(31) })).toThrow(/32 bytes/);
		expect(() => createAuthConfig({ ...base, secret: "a".repeat(32) })).not.toThrow();
	});

	it("is Secure by default whatever NODE_ENV says", () => {
		expect(createAuthConfig({ ...base, secret: TEST_SECRET, isProd: false }).secure).toBe(true);
		expect(createAuthConfig({ ...base, secret: TEST_SECRET }).secure).toBe(true);
	});

	it("allows an explicit secure:false and then never uses the __Host- prefix", () => {
		const c = createAuthConfig({ ...base, secret: TEST_SECRET, secure: false, isProd: true });
		expect(c.secure).toBe(false);
		expect(c.cookies.sessionName).toBe("glinr-token");
		expect(c.cookies.cacheName).toBe("glinr-session-cache");
	});

	it("does not expose the secret as an enumerable property", () => {
		const c = createAuthConfig({ ...base, secret: TEST_SECRET });
		expect(JSON.stringify(c)).not.toContain(TEST_SECRET);
	});
});
