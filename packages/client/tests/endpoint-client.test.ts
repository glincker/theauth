import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { createEndpointClient } from "../src/endpoint-client.js";

type Api = {
	"POST /team/:teamId/invite": {
		params: { teamId: string };
		query: { notify?: "yes" | "no" };
		body: { email: string };
		response: { invited: string };
	};
	"GET /ping": {
		params: undefined;
		query: undefined;
		body: undefined;
		response: { pong: boolean };
	};
};

function mockFetch(status: number, body: unknown) {
	return vi.fn(async (_url: string, _init?: RequestInit) => {
		return new Response(JSON.stringify(body), { status });
	});
}

describe("createEndpointClient", () => {
	it("fills path params, sends query and a JSON body", async () => {
		const fetchMock = mockFetch(200, { invited: "a@b.co" });
		const api = createEndpointClient<Api>({
			baseUrl: "/api/theauth/",
			fetch: fetchMock as unknown as typeof fetch,
			headers: { Authorization: "Bearer t" },
		});

		const out = await api.call("POST /team/:teamId/invite", {
			params: { teamId: "t 1" },
			query: { notify: "no" },
			body: { email: "a@b.co" },
		});

		expect(out).toEqual({ ok: true, status: 200, data: { invited: "a@b.co" } });
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/api/theauth/team/t%201/invite?notify=no");
		expect(init.method).toBe("POST");
		expect(init.body).toBe('{"email":"a@b.co"}');
		const headers = init.headers as Headers;
		expect(headers.get("authorization")).toBe("Bearer t");
		expect(headers.get("content-type")).toBe("application/json");
		expect(init.credentials).toBe("include");
	});

	it("needs no input for a route without any", async () => {
		const fetchMock = mockFetch(200, { pong: true });
		const api = createEndpointClient<Api>({
			baseUrl: "https://api.example.com/auth",
			fetch: fetchMock as unknown as typeof fetch,
		});
		const out = await api.call("GET /ping");
		expect(out.ok).toBe(true);
		expect((fetchMock.mock.calls[0] as [string])[0]).toBe("https://api.example.com/auth/ping");
	});

	it("returns validation issues from the server instead of throwing", async () => {
		const api = createEndpointClient<Api>({
			baseUrl: "/a",
			fetch: mockFetch(400, {
				error: { code: "INVALID_INPUT", message: "bad", issues: [{ path: "email" }] },
			}) as unknown as typeof fetch,
		});
		const out = await api.call("POST /team/:teamId/invite", {
			params: { teamId: "t" },
			body: { email: "x" },
		});
		expect(out).toMatchObject({ ok: false, status: 400, error: { code: "INVALID_INPUT" } });
	});

	it("throws for a missing path parameter", async () => {
		const api = createEndpointClient<Api>({
			baseUrl: "/a",
			fetch: mockFetch(200, {}) as unknown as typeof fetch,
		});
		await expect(
			api.call("POST /team/:teamId/invite", {
				params: {} as { teamId: string },
				body: { email: "a@b.co" },
			}),
		).rejects.toThrow('Missing path parameter "teamId"');
	});

	it("infers the response type from the route key", async () => {
		const api = createEndpointClient<Api>({
			baseUrl: "/a",
			fetch: mockFetch(200, { pong: true }) as unknown as typeof fetch,
		});
		const out = await api.call("GET /ping");
		if (out.ok) expectTypeOf(out.data).toEqualTypeOf<{ pong: boolean }>();
	});
});
