import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthConfig } from "../src/config.js";

// ---------------------------------------------------------------------------
// Tests for graphqlWithRefresh UNAUTHENTICATED error code detection + retry.
// Covers the case where the backend returns HTTP 200 with GraphQL errors that
// carry extensions.code === "UNAUTHENTICATED" or "UNAUTHORIZED".
// ---------------------------------------------------------------------------

vi.mock("server-only", () => ({}));

const mockCookieStore = {
	get: vi.fn(),
	set: vi.fn(),
	delete: vi.fn(),
};

vi.mock("next/headers", () => ({
	cookies: vi.fn().mockResolvedValue(mockCookieStore),
}));

const { graphqlWithRefresh, GraphQLRequestError } = await import("../src/backend-fetch.js");

const config = createAuthConfig({
	backendUrl: "https://api.example.com",
	appUrl: "https://example.com",
	isProd: false,
	endpoints: { refresh: "/api/auth/refresh" },
	cookies: { sessionPrefix: "glinr" },
});

/** Make a minimal JWT that expires far in the future (no signature needed for tests). */
function makeJwt(payload: Record<string, unknown>): string {
	const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
	const body = btoa(JSON.stringify(payload));
	return `${header}.${body}.sig`;
}

describe("graphqlWithRefresh — UNAUTHENTICATED error code", () => {
	let fetchMock: MockInstance;

	beforeEach(() => {
		vi.clearAllMocks();
		fetchMock = vi.spyOn(global, "fetch");

		// Provide a valid access token cookie so buildAuthHeaders doesn't bail.
		const futureJwt = makeJwt({ sub: "user-1", exp: Math.floor(Date.now() / 1000) + 3600 });
		mockCookieStore.get.mockImplementation((name: string) => {
			if (name === "glinr-token" || name === "__Host-glinr-token") {
				return { value: futureJwt };
			}
			if (name === "glinr-csrf" || name === "__Host-glinr-csrf") {
				return { value: "csrf-token" };
			}
			if (name === config.cookies.refresh) {
				return { value: "valid-refresh-token" };
			}
			return undefined;
		});
	});

	it("retries and returns data when backend returns HTTP 200 UNAUTHENTICATED then success", async () => {
		// First call: HTTP 200 with UNAUTHENTICATED error
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					errors: [
						{
							message: "Auth required",
							extensions: { code: "UNAUTHENTICATED" },
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		// Refresh call: success
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({ accessToken: "new-access-token", refreshToken: "new-refresh-token" }),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		// Second GraphQL call: success
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ data: { foo: "bar" } }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const result = await graphqlWithRefresh<{ foo: string }, unknown>(config, "query { foo }");

		expect(result).toEqual({ foo: "bar" });
		// graphql fetch x2 + refresh fetch x1 = 3 total
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});

	it("retries and returns data when backend returns HTTP 200 UNAUTHORIZED then success", async () => {
		// First call: HTTP 200 with UNAUTHORIZED error (Hasura/GraphQL-Java convention)
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					errors: [
						{
							message: "Unauthorized",
							extensions: { code: "UNAUTHORIZED" },
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		// Refresh call: success
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ accessToken: "new-access-token" }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		// Second GraphQL call: success
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ data: { user: { id: "42" } } }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const result = await graphqlWithRefresh<{ user: { id: string } }, unknown>(
			config,
			"query { user { id } }",
		);

		expect(result).toEqual({ user: { id: "42" } });
	});

	it("throws GraphQLRequestError when UNAUTHENTICATED and refresh fails", async () => {
		// First call: HTTP 200 with UNAUTHENTICATED error
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					errors: [{ message: "Auth required", extensions: { code: "UNAUTHENTICATED" } }],
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		// Refresh call: fails (401)
		fetchMock.mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));

		await expect(graphqlWithRefresh(config, "query { foo }")).rejects.toBeInstanceOf(
			GraphQLRequestError,
		);
	});

	it("does NOT retry for non-auth GraphQL errors", async () => {
		// First call: HTTP 200 with a regular (non-auth) error
		fetchMock.mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					errors: [{ message: "Field not found", extensions: { code: "BAD_USER_INPUT" } }],
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		await expect(graphqlWithRefresh(config, "query { foo }")).rejects.toBeInstanceOf(
			GraphQLRequestError,
		);

		// Only 1 fetch — no refresh, no retry
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("throws typed GraphQLRequestError on non-JSON 401 (WAF/load-balancer plain text)", async () => {
		// HTTP 401 with a plain-text body (like a WAF or nginx default error page)
		fetchMock.mockResolvedValueOnce(
			new Response("Access denied", {
				status: 401,
				headers: { "Content-Type": "text/plain" },
			}),
		);

		// Refresh call: fails
		fetchMock.mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));

		const error = await graphqlWithRefresh(config, "query { foo }").catch((e: unknown) => e);

		expect(error).toBeInstanceOf(GraphQLRequestError);
		expect((error as GraphQLRequestError).status).toBe(401);
	});
});
