import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "../src/config.js";

// ---------------------------------------------------------------------------
// We test the refresh logic in isolation by mocking:
//   1. The `next/headers` cookies store (via vi.mock)
//   2. global.fetch
//
// The actual refreshSession() function imports server-only and cookies() from
// next/headers — we mock both at the module level.
// ---------------------------------------------------------------------------

// Mock server-only so the import doesn't throw in Node test env.
vi.mock("server-only", () => ({}));

// Provide a minimal mock cookies store.
const mockCookieStore = {
	get: vi.fn(),
	set: vi.fn(),
	delete: vi.fn(),
};

vi.mock("next/headers", () => ({
	cookies: vi.fn().mockResolvedValue(mockCookieStore),
}));

// Import after mocks are set up.
const { refreshSession } = await import("../src/refresh.js");

const config = createAuthConfig({
	backendUrl: "https://api.example.com",
	appUrl: "https://example.com",
	isProd: false,
	endpoints: { refresh: "/api/auth/refresh" },
	cookies: { sessionPrefix: "glinr" },
});

describe("refreshSession", () => {
	let fetchMock: MockInstance;

	beforeEach(() => {
		vi.clearAllMocks();
		fetchMock = vi.spyOn(global, "fetch");
	});

	it("returns null when no refresh cookie is present", async () => {
		mockCookieStore.get.mockReturnValue(undefined);

		const result = await refreshSession(config);

		expect(result).toBeNull();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("returns tokens and writes cookies on successful refresh", async () => {
		mockCookieStore.get.mockImplementation((name: string) => {
			if (name === config.cookies.refresh) {
				return { value: "valid-refresh-token" };
			}
			return undefined;
		});

		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({ accessToken: "new-access-token", refreshToken: "new-refresh-token" }),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		const result = await refreshSession(config);

		expect(result).not.toBeNull();
		expect(result?.accessToken).toBe("new-access-token");
		expect(result?.refreshToken).toBe("new-refresh-token");
		expect(typeof result?.csrfToken).toBe("string");
		expect(result?.csrfToken.length).toBeGreaterThan(0);

		// Verify cookies were written
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			config.cookies.sessionName,
			"new-access-token",
			expect.objectContaining({ httpOnly: true }),
		);
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			config.cookies.csrfName,
			expect.any(String),
			expect.objectContaining({ httpOnly: false }),
		);
	});

	it("clears cookies and returns null on 401 from backend", async () => {
		mockCookieStore.get.mockImplementation((name: string) => {
			if (name === config.cookies.refresh) {
				return { value: "expired-refresh-token" };
			}
			return undefined;
		});

		fetchMock.mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));

		const result = await refreshSession(config);

		expect(result).toBeNull();
		// All session cookies should be cleared
		expect(mockCookieStore.delete).toHaveBeenCalledWith("__Host-glinr-token");
		expect(mockCookieStore.delete).toHaveBeenCalledWith("glinr-token");
		expect(mockCookieStore.delete).toHaveBeenCalledWith("__Host-glinr-csrf");
		expect(mockCookieStore.delete).toHaveBeenCalledWith("glinr-csrf");
		expect(mockCookieStore.delete).toHaveBeenCalledWith(config.cookies.refresh);
	});

	it("clears cookies and returns null on 403 from backend", async () => {
		mockCookieStore.get.mockImplementation((name: string) => {
			if (name === config.cookies.refresh) {
				return { value: "revoked-token" };
			}
			return undefined;
		});

		fetchMock.mockResolvedValueOnce(new Response("Forbidden", { status: 403 }));

		const result = await refreshSession(config);

		expect(result).toBeNull();
		expect(mockCookieStore.delete).toHaveBeenCalledWith("glinr-token");
	});

	it("returns null on network error without clearing cookies", async () => {
		mockCookieStore.get.mockImplementation((name: string) => {
			if (name === config.cookies.refresh) {
				return { value: "some-token" };
			}
			return undefined;
		});

		fetchMock.mockRejectedValueOnce(new Error("Network error"));

		const result = await refreshSession(config);

		expect(result).toBeNull();
		expect(mockCookieStore.delete).not.toHaveBeenCalled();
	});

	it("returns null when backend returns 200 but no accessToken in body", async () => {
		mockCookieStore.get.mockImplementation((name: string) => {
			if (name === config.cookies.refresh) {
				return { value: "valid-refresh-token" };
			}
			return undefined;
		});

		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ message: "ok" }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const result = await refreshSession(config);
		expect(result).toBeNull();
	});
});
