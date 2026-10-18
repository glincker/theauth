import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "../src/config.js";

const TEST_SECRET = "test-secret-test-secret-test-secret-0123456789";

// refreshSession is tested in isolation: next/headers cookies() and global fetch are mocked.
vi.mock("server-only", () => ({}));

const mockCookieStore = {
	get: vi.fn(),
	set: vi.fn(),
	delete: vi.fn(),
};

vi.mock("next/headers", () => ({
	cookies: vi.fn().mockResolvedValue(mockCookieStore),
}));

const { refreshSession } = await import("../src/refresh.js");

const config = createAuthConfig({
	secret: TEST_SECRET,
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
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			"__Host-glinr-token",
			"",
			expect.objectContaining({ maxAge: 0 }),
		);
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			"glinr-token",
			"",
			expect.objectContaining({ maxAge: 0 }),
		);
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			"__Host-glinr-csrf",
			"",
			expect.objectContaining({ maxAge: 0 }),
		);
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			"glinr-csrf",
			"",
			expect.objectContaining({ maxAge: 0 }),
		);
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			config.cookies.refresh,
			"",
			expect.objectContaining({ maxAge: 0 }),
		);
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
		expect(mockCookieStore.set).toHaveBeenCalledWith(
			"glinr-token",
			"",
			expect.objectContaining({ maxAge: 0 }),
		);
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
