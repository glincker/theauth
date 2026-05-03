import { describe, expect, it } from "vitest";
import { createAuthConfig } from "../src/config.js";

// We test the cookie name derivation and config resolution logic here.
// The actual next/headers + NextResponse cookie helpers are integration-tested
// against the Next.js runtime; unit tests mock-out those boundaries.

describe("createAuthConfig — cookie name resolution", () => {
	it("uses __Host- prefix when isProd=true", () => {
		const config = createAuthConfig({
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: true,
		});
		expect(config.cookies.sessionName).toBe("__Host-glinr-token");
		expect(config.cookies.csrfName).toBe("__Host-glinr-csrf");
	});

	it("uses plain prefix when isProd=false", () => {
		const config = createAuthConfig({
			backendUrl: "http://localhost:9100",
			appUrl: "http://localhost:3000",
			isProd: false,
		});
		expect(config.cookies.sessionName).toBe("glinr-token");
		expect(config.cookies.csrfName).toBe("glinr-csrf");
	});

	it("uses custom sessionPrefix for cookie names", () => {
		const config = createAuthConfig({
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: true,
			cookies: { sessionPrefix: "myapp" },
		});
		expect(config.cookies.sessionName).toBe("__Host-myapp-token");
		expect(config.cookies.csrfName).toBe("__Host-myapp-csrf");
		expect(config.cookies.refresh).toBe("myapp-refresh-token");
		expect(config.cookies.cacheName).toBe("myapp-session-cache");
	});

	it("allows custom refresh cookie name override", () => {
		const config = createAuthConfig({
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			isProd: false,
			cookies: { refresh: "my-custom-refresh" },
		});
		expect(config.cookies.refresh).toBe("my-custom-refresh");
	});

	it("strips trailing slashes from backendUrl and appUrl", () => {
		const config = createAuthConfig({
			backendUrl: "https://api.example.com/",
			appUrl: "https://example.com/",
			isProd: true,
		});
		expect(config.backendUrl).toBe("https://api.example.com");
		expect(config.appUrl).toBe("https://example.com");
	});

	it("applies default endpoint paths", () => {
		const config = createAuthConfig({
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		expect(config.endpoints.me).toBe("/api/auth/me");
		expect(config.endpoints.refresh).toBe("/api/auth/refresh");
		expect(config.endpoints.signOut).toBe("/api/auth/logout");
	});

	it("respects endpoint overrides", () => {
		const config = createAuthConfig({
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
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		expect(config.cookieCacheMaxAgeMs).toBe(5 * 60 * 1000);
	});

	it("applies default expiryRefreshBufferS of 60", () => {
		const config = createAuthConfig({
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
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
			mapUser,
		});
		expect(config.mapUser).toBe(mapUser);
	});

	it("uses default mapUser that returns raw as TUser when none provided", () => {
		const config = createAuthConfig({
			backendUrl: "https://api.example.com",
			appUrl: "https://example.com",
		});
		const raw = { id: "123", email: "test@example.com" };
		expect(config.mapUser(raw)).toEqual(raw);
		expect(config.mapUser(null)).toBeNull();
	});
});
