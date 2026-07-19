import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthClient } from "../src/client.js";
import { AuthApiError } from "../src/error.js";
import type { Agent, CreateAgentInput } from "../src/types.js";

// Renamed from Kavach* to Auth* -- use new names throughout
const createKavachClient = createAuthClient;
const KavachApiError = AuthApiError;
type KavachApiError = AuthApiError;

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function mockFetch(status: number, body: unknown): void {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue({
			ok: status >= 200 && status < 300,
			status,
			json: () => Promise.resolve(body),
			text: () => Promise.resolve(typeof body === "string" ? body : JSON.stringify(body)),
		}),
	);
}

function capturedFetch(): ReturnType<typeof vi.fn> {
	return globalThis.fetch as ReturnType<typeof vi.fn>;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_URL = "https://api.example.com";

const AGENT_FIXTURE: Agent = {
	id: "agent-1",
	ownerId: "user-1",
	name: "Test Agent",
	type: "autonomous",
	token: "tok_abc123",
	permissions: [{ resource: "files", actions: ["read"] }],
	status: "active",
	expiresAt: null,
	createdAt: "2026-01-01T00:00:00.000Z",
	updatedAt: "2026-01-01T00:00:00.000Z",
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createKavachClient", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("returns a client object with the expected shape", () => {
		const client = createKavachClient({ baseUrl: BASE_URL });
		expect(typeof client.agents.create).toBe("function");
		expect(typeof client.agents.get).toBe("function");
		expect(typeof client.agents.list).toBe("function");
		expect(typeof client.agents.update).toBe("function");
		expect(typeof client.agents.revoke).toBe("function");
		expect(typeof client.agents.rotate).toBe("function");
		expect(typeof client.authorize).toBe("function");
		expect(typeof client.authorizeByToken).toBe("function");
		expect(typeof client.delegations.create).toBe("function");
		expect(typeof client.delegations.list).toBe("function");
		expect(typeof client.delegations.revoke).toBe("function");
		expect(typeof client.delegations.getEffectivePermissions).toBe("function");
		expect(typeof client.audit.query).toBe("function");
		expect(typeof client.audit.export).toBe("function");
		expect(typeof client.mcp.list).toBe("function");
		expect(typeof client.mcp.get).toBe("function");
		expect(typeof client.mcp.register).toBe("function");
	});

	describe("agents.create", () => {
		beforeEach(() => {
			mockFetch(201, AGENT_FIXTURE);
		});

		it("sends POST /agents with the input body", async () => {
			const client = createKavachClient({ baseUrl: BASE_URL });
			const input: CreateAgentInput = {
				ownerId: "user-1",
				name: "Test Agent",
				type: "autonomous",
				permissions: [{ resource: "files", actions: ["read"] }],
			};

			const result = await client.agents.create(input);

			const fetchMock = capturedFetch();
			expect(fetchMock).toHaveBeenCalledOnce();
			const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
			expect(url).toBe(`${BASE_URL}/agents`);
			expect(init.method).toBe("POST");
			expect(JSON.parse(init.body as string)).toEqual(input);
			expect(result).toEqual(AGENT_FIXTURE);
		});

		it("includes Authorization header when token is provided", async () => {
			const client = createKavachClient({
				baseUrl: BASE_URL,
				token: "my-token",
			});
			await client.agents.create({
				ownerId: "user-1",
				name: "Test Agent",
				type: "service",
				permissions: [],
			});

			const fetchMock = capturedFetch();
			const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
			const headers = init.headers as Record<string, string>;
			expect(headers.Authorization).toBe("Bearer my-token");
		});

		it("does not include Authorization header when no token is provided", async () => {
			const client = createKavachClient({ baseUrl: BASE_URL });
			await client.agents.create({
				ownerId: "user-1",
				name: "Test Agent",
				type: "service",
				permissions: [],
			});

			const fetchMock = capturedFetch();
			const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
			const headers = init.headers as Record<string, string>;
			expect(headers.Authorization).toBeUndefined();
		});
	});

	describe("agents.get", () => {
		it("returns the agent when found", async () => {
			mockFetch(200, AGENT_FIXTURE);
			const client = createKavachClient({ baseUrl: BASE_URL });
			const result = await client.agents.get("agent-1");
			expect(result).toEqual(AGENT_FIXTURE);
		});

		it("returns null on 404", async () => {
			mockFetch(404, { code: "NOT_FOUND", message: "Agent not found" });
			const client = createKavachClient({ baseUrl: BASE_URL });
			const result = await client.agents.get("missing-id");
			expect(result).toBeNull();
		});
	});

	describe("agents.list", () => {
		it("sends GET /agents without filters", async () => {
			mockFetch(200, [AGENT_FIXTURE]);
			const client = createKavachClient({ baseUrl: BASE_URL });
			const result = await client.agents.list();

			const [url] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toBe(`${BASE_URL}/agents`);
			expect(result).toEqual([AGENT_FIXTURE]);
		});

		it("appends query string when filters are provided", async () => {
			mockFetch(200, []);
			const client = createKavachClient({ baseUrl: BASE_URL });
			await client.agents.list({ status: "active", type: "autonomous" });

			const [url] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toContain("status=active");
			expect(url).toContain("type=autonomous");
		});
	});

	describe("agents.revoke", () => {
		it("sends DELETE and returns void", async () => {
			mockFetch(204, "");
			const client = createKavachClient({ baseUrl: BASE_URL });
			const result = await client.agents.revoke("agent-1");

			const [url, init] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toBe(`${BASE_URL}/agents/agent-1`);
			expect(init.method).toBe("DELETE");
			expect(result).toBeUndefined();
		});
	});

	describe("agents.rotate", () => {
		it("sends POST to the rotate endpoint and returns the updated agent", async () => {
			const rotated = { ...AGENT_FIXTURE, token: "new-token-xyz" };
			mockFetch(200, rotated);
			const client = createKavachClient({ baseUrl: BASE_URL });
			const result = await client.agents.rotate("agent-1");

			const [url, init] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toBe(`${BASE_URL}/agents/agent-1/rotate`);
			expect(init.method).toBe("POST");
			expect(result.token).toBe("new-token-xyz");
		});
	});

	describe("error handling", () => {
		it("throws KavachApiError with status and code on non-ok responses", async () => {
			mockFetch(403, { code: "PERMISSION_DENIED", message: "Access denied" });
			const client = createKavachClient({ baseUrl: BASE_URL });

			await expect(client.agents.list()).rejects.toThrow(KavachApiError);

			mockFetch(403, { code: "PERMISSION_DENIED", message: "Access denied" });
			try {
				await client.agents.list();
			} catch (err) {
				expect(err).toBeInstanceOf(AuthApiError);
				const apiErr = err as AuthApiError;
				expect(apiErr.status).toBe(403);
				expect(apiErr.code).toBe("PERMISSION_DENIED");
				expect(apiErr.message).toBe("Access denied");
				expect(apiErr.name).toBe("TheAuthApiError");
			}
		});

		it("falls back to default code and message when error body is not JSON", async () => {
			vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
					ok: false,
					status: 500,
					json: () => Promise.reject(new SyntaxError("not json")),
					text: () => Promise.resolve("Internal Server Error"),
				}),
			);

			const client = createKavachClient({ baseUrl: BASE_URL });

			await expect(client.agents.list()).rejects.toThrow(KavachApiError);

			vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue({
					ok: false,
					status: 500,
					json: () => Promise.reject(new SyntaxError("not json")),
					text: () => Promise.resolve("Internal Server Error"),
				}),
			);
			try {
				await client.agents.list();
			} catch (err) {
				const apiErr = err as KavachApiError;
				expect(apiErr.status).toBe(500);
				expect(apiErr.code).toBe("API_ERROR");
				expect(apiErr.message).toBe("HTTP 500");
			}
		});

		it("supports nested { error: { code, message } } error shape", async () => {
			mockFetch(422, {
				error: { code: "VALIDATION_FAILED", message: "Invalid input" },
			});
			const client = createKavachClient({ baseUrl: BASE_URL });

			try {
				await client.agents.list();
			} catch (err) {
				const apiErr = err as KavachApiError;
				expect(apiErr.status).toBe(422);
				expect(apiErr.code).toBe("VALIDATION_FAILED");
				expect(apiErr.message).toBe("Invalid input");
			}
		});
	});

	describe("authorize", () => {
		it("sends POST to /agents/:id/authorize", async () => {
			mockFetch(200, { allowed: true, auditId: "audit-1" });
			const client = createKavachClient({ baseUrl: BASE_URL, token: "tok" });
			const result = await client.authorize("agent-1", {
				action: "read",
				resource: "files",
			});

			const [url, init] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toBe(`${BASE_URL}/agents/agent-1/authorize`);
			expect(init.method).toBe("POST");
			expect(result.allowed).toBe(true);
		});
	});

	describe("authorizeByToken", () => {
		it("overrides Authorization header with the agent token", async () => {
			mockFetch(200, { allowed: false, reason: "denied", auditId: "audit-2" });
			const client = createKavachClient({
				baseUrl: BASE_URL,
				token: "client-token",
			});
			await client.authorizeByToken("agent-specific-token", {
				action: "write",
				resource: "db",
			});

			const [url, init] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toBe(`${BASE_URL}/authorize`);
			const headers = init.headers as Record<string, string>;
			expect(headers.Authorization).toBe("Bearer agent-specific-token");
		});
	});

	describe("extra headers", () => {
		it("merges extra headers into every request", async () => {
			mockFetch(200, []);
			const client = createKavachClient({
				baseUrl: BASE_URL,
				headers: { "X-Tenant-Id": "tenant-42" },
			});
			await client.agents.list();

			const [, init] = capturedFetch().mock.calls[0] as [string, RequestInit];
			const headers = init.headers as Record<string, string>;
			expect(headers["X-Tenant-Id"]).toBe("tenant-42");
		});
	});

	describe("baseUrl trailing slash", () => {
		it("normalises a trailing slash in baseUrl", async () => {
			mockFetch(200, []);
			const client = createKavachClient({
				baseUrl: "https://api.example.com/",
			});
			await client.agents.list();

			const [url] = capturedFetch().mock.calls[0] as [string, RequestInit];
			expect(url).toBe("https://api.example.com/agents");
		});
	});
});
