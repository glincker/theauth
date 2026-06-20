import { randomUUID } from "node:crypto";
import * as jose from "jose";
import { describe, expect, it } from "vitest";
import {
	createAgentCard,
	signAgentCard,
	validateAgentCard,
	verifyAgentCard,
} from "../src/a2a/agent-card.js";
import { createA2AClient } from "../src/a2a/client.js";
import { createA2AServer } from "../src/a2a/server.js";
import type { A2AAgentCard, A2AAuditEvent, A2AMessage, A2ATask } from "../src/a2a/types.js";
import {
	A2A_ERROR_CODES,
	A2A_JSONRPC_VERSION,
	A2A_METHODS,
	A2A_PROTOCOL_VERSION,
	A2A_WELL_KNOWN_PATH,
	A2AMessageSchema,
	A2APartSchema,
	A2ATaskStateSchema,
} from "../src/a2a/types.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeAgentCard(overrides?: Partial<A2AAgentCard>): A2AAgentCard {
	return {
		id: randomUUID(),
		name: "Test Agent",
		description: "A test agent for unit testing",
		version: "1.0.0",
		protocolVersion: A2A_PROTOCOL_VERSION,
		url: "https://agent.example.com/a2a",
		skills: [
			{
				id: "echo",
				name: "Echo",
				description: "Echoes back the input",
			},
		],
		...overrides,
	};
}

function makeMessage(text = "Hello"): A2AMessage {
	return {
		id: randomUUID(),
		role: "user",
		parts: [{ type: "text", text }],
		createdAt: new Date().toISOString(),
	};
}

function makeTask(overrides?: Partial<A2ATask>): A2ATask {
	const now = new Date().toISOString();
	return {
		id: randomUUID(),
		contextId: randomUUID(),
		status: { code: "completed" },
		createdAt: now,
		updatedAt: now,
		...overrides,
	};
}

// ─── Agent Card Creation ─────────────────────────────────────────────────────

describe("A2A Agent Card", () => {
	describe("createAgentCard", () => {
		it("creates a card from a TheAuth agent identity", () => {
			const card = createAgentCard({
				agent: { id: "agent-1", name: "Code Reviewer", type: "service" },
				url: "https://agent.example.com/a2a",
				description: "Reviews pull requests",
				version: "2.0.0",
				skills: [
					{
						id: "review",
						name: "Code Review",
						description: "Reviews code changes",
					},
				],
			});

			expect(card.id).toBe("agent-1");
			expect(card.name).toBe("Code Reviewer");
			expect(card.protocolVersion).toBe(A2A_PROTOCOL_VERSION);
			expect(card.url).toBe("https://agent.example.com/a2a");
			expect(card.skills).toHaveLength(1);
			expect(card.skills[0]?.name).toBe("Code Review");
		});

		it("includes optional provider and capabilities", () => {
			const card = createAgentCard({
				agent: { id: "agent-2", name: "Helper", type: "autonomous" },
				url: "https://helper.example.com/a2a",
				description: "A helpful agent",
				version: "1.0.0",
				skills: [{ id: "help", name: "Help", description: "Helps" }],
				provider: { name: "Acme Corp", email: "hello@acme.com" },
				capabilities: { streaming: true, pushNotifications: false },
				defaultInputModes: ["text/plain"],
				defaultOutputModes: ["text/plain", "application/json"],
			});

			expect(card.provider?.name).toBe("Acme Corp");
			expect(card.capabilities?.streaming).toBe(true);
			expect(card.defaultInputModes).toEqual(["text/plain"]);
		});

		it("includes security schemes for OAuth2", () => {
			const card = createAgentCard({
				agent: { id: "agent-3", name: "Secure Agent", type: "service" },
				url: "https://secure.example.com/a2a",
				description: "Requires OAuth2",
				version: "1.0.0",
				skills: [{ id: "s1", name: "Secure", description: "Secure skill" }],
				securitySchemes: {
					oauth2: {
						type: "oauth2",
						flows: {
							clientCredentials: {
								tokenUrl: "https://auth.example.com/token",
								scopes: { "a2a:read": "Read access" },
							},
						},
					},
				},
				security: [{ oauth2: ["a2a:read"] }],
			});

			expect(card.securitySchemes?.oauth2?.type).toBe("oauth2");
			expect(card.security?.[0]).toEqual({ oauth2: ["a2a:read"] });
		});

		it("includes metadata and documentation URL", () => {
			const card = createAgentCard({
				agent: { id: "agent-4", name: "Documented", type: "delegated" },
				url: "https://doc.example.com/a2a",
				description: "Well documented",
				version: "1.0.0",
				skills: [{ id: "s1", name: "Skill", description: "A skill" }],
				documentationUrl: "https://docs.example.com/agent",
				metadata: { region: "us-east-1" },
			});

			expect(card.documentationUrl).toBe("https://docs.example.com/agent");
			expect(card.metadata?.region).toBe("us-east-1");
		});
	});

	// ─── Agent Card Validation ───────────────────────────────────────────────

	describe("validateAgentCard", () => {
		it("validates a correct agent card", () => {
			const card = makeAgentCard();
			const result = validateAgentCard(card);
			expect(result.success).toBe(true);
		});

		it("rejects a card missing required name", () => {
			const { name, ...incomplete } = makeAgentCard();
			const result = validateAgentCard(incomplete);
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("A2A_INVALID_AGENT_CARD");
			}
		});

		it("rejects a card missing required skills", () => {
			const card = makeAgentCard({ skills: [] });
			const result = validateAgentCard(card);
			expect(result.success).toBe(false);
		});

		it("rejects a card with invalid URL", () => {
			const card = makeAgentCard({ url: "not-a-url" });
			const result = validateAgentCard(card);
			expect(result.success).toBe(false);
		});

		it("rejects a card missing id", () => {
			const { id, ...incomplete } = makeAgentCard();
			const result = validateAgentCard(incomplete);
			expect(result.success).toBe(false);
		});

		it("rejects a non-object input", () => {
			const result = validateAgentCard("not an object");
			expect(result.success).toBe(false);
		});

		it("rejects null input", () => {
			const result = validateAgentCard(null);
			expect(result.success).toBe(false);
		});

		it("validates card with all optional fields", () => {
			const card = makeAgentCard({
				provider: { name: "Test" },
				capabilities: { streaming: true },
				securitySchemes: {
					bearer: { type: "http", scheme: "bearer" },
				},
				defaultInputModes: ["text/plain"],
				defaultOutputModes: ["application/json"],
				documentationUrl: "https://docs.example.com",
				metadata: { foo: "bar" },
			});
			const result = validateAgentCard(card);
			expect(result.success).toBe(true);
		});
	});

	// ─── Agent Card Signing & Verification ───────────────────────────────────

	describe("signAgentCard", () => {
		it("signs a card with an EC key", async () => {
			const { privateKey } = await jose.generateKeyPair("ES256");
			const card = makeAgentCard();

			const result = await signAgentCard({ card, privateKey });
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.signature).toBeDefined();
				expect(result.data.signature?.algorithm).toBe("ES256");
				expect(result.data.signature?.signature).toBeTruthy();
				expect(result.data.signature?.keyId).toBeTruthy();
			}
		});

		it("signs with a custom key ID", async () => {
			const { privateKey } = await jose.generateKeyPair("ES256");
			const card = makeAgentCard();

			const result = await signAgentCard({
				card,
				privateKey,
				keyId: "my-key-id",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.signature?.keyId).toBe("my-key-id");
			}
		});

		it("returns error for invalid key", async () => {
			const card = makeAgentCard();
			// Pass an invalid key
			const result = await signAgentCard({
				card,
				privateKey: { kty: "EC" } as jose.JWK,
				algorithm: "ES256",
			});
			expect(result.success).toBe(false);
		});
	});

	describe("verifyAgentCard", () => {
		it("verifies a validly signed card", async () => {
			const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
			const card = makeAgentCard();

			const signed = await signAgentCard({ card, privateKey });
			expect(signed.success).toBe(true);
			if (!signed.success) return;

			const verified = await verifyAgentCard({
				card: signed.data,
				publicKey,
			});
			expect(verified.success).toBe(true);
			if (verified.success) {
				expect(verified.data.valid).toBe(true);
			}
		});

		it("rejects a tampered card", async () => {
			const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
			const card = makeAgentCard();

			const signed = await signAgentCard({ card, privateKey });
			expect(signed.success).toBe(true);
			if (!signed.success) return;

			// Tamper with the card
			const tampered = { ...signed.data, name: "Tampered Agent" };

			const verified = await verifyAgentCard({
				card: tampered,
				publicKey,
			});
			expect(verified.success).toBe(true);
			if (verified.success) {
				expect(verified.data.valid).toBe(false);
			}
		});

		it("rejects a card with no signature", async () => {
			const { publicKey } = await jose.generateKeyPair("ES256");
			const card = makeAgentCard();

			const result = await verifyAgentCard({ card, publicKey });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("A2A_NO_SIGNATURE");
			}
		});

		it("rejects verification with wrong key", async () => {
			const { privateKey } = await jose.generateKeyPair("ES256");
			const { publicKey: wrongKey } = await jose.generateKeyPair("ES256");
			const card = makeAgentCard();

			const signed = await signAgentCard({ card, privateKey });
			expect(signed.success).toBe(true);
			if (!signed.success) return;

			const verified = await verifyAgentCard({
				card: signed.data,
				publicKey: wrongKey,
			});
			// Should fail because the signature doesn't match the wrong key
			expect(verified.success).toBe(false);
		});
	});
});

// ─── A2A Server ──────────────────────────────────────────────────────────────

describe("A2A Server", () => {
	function createTestServer(options?: {
		authenticate?: (req: Request) => Promise<string | null>;
		onAudit?: (event: A2AAuditEvent) => Promise<void>;
	}) {
		const card = makeAgentCard();
		return createA2AServer({
			agentCard: card,
			handler: {
				onMessage: async (message) =>
					makeTask({
						history: [message],
						artifacts: [
							{
								id: randomUUID(),
								parts: [
									{ type: "text", text: `Echo: ${(message.parts[0] as { text: string }).text}` },
								],
								createdAt: new Date().toISOString(),
							},
						],
					}),
				onCancel: async (taskId) =>
					makeTask({
						id: taskId,
						status: { code: "canceled", message: "Canceled by handler" },
					}),
			},
			...options,
		});
	}

	function jsonRpcRequest(method: string, params: unknown, id: string | number = 1): Request {
		return new Request("https://agent.example.com/a2a", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				jsonrpc: A2A_JSONRPC_VERSION,
				id,
				method,
				params,
			}),
		});
	}

	describe("agent card discovery", () => {
		it("serves agent card at /.well-known/agent.json", async () => {
			const server = createTestServer();
			const req = new Request(`https://agent.example.com${A2A_WELL_KNOWN_PATH}`, {
				method: "GET",
			});
			const res = await server.handleRequest(req);
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.name).toBe("Test Agent");
			expect(body.protocolVersion).toBe(A2A_PROTOCOL_VERSION);
		});
	});

	describe("message/send", () => {
		it("handles a valid send message request", async () => {
			const server = createTestServer();
			const msg = makeMessage("Test input");
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, {
				message: msg,
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.result).toBeDefined();
			expect(body.result.status.code).toBe("completed");
			expect(body.result.artifacts).toHaveLength(1);
		});

		it("rejects invalid params", async () => {
			const server = createTestServer();
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, {
				message: { invalid: true },
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error).toBeDefined();
			expect(body.error.code).toBe(A2A_ERROR_CODES.INVALID_PARAMS);
		});

		it("stores the task after handling", async () => {
			const server = createTestServer();
			const msg = makeMessage("Store me");
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, {
				message: msg,
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			const taskId = body.result.id;

			const stored = await server.taskStore.get(taskId);
			expect(stored).toBeDefined();
			expect(stored?.id).toBe(taskId);
		});
	});

	describe("tasks/get", () => {
		it("retrieves a stored task", async () => {
			const server = createTestServer();
			// First send a message to create a task
			const msg = makeMessage("Create task");
			const sendReq = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			const sendRes = await server.handleRequest(sendReq);
			const sendBody = await sendRes.json();
			const taskId = sendBody.result.id;

			// Now get the task
			const getReq = jsonRpcRequest(A2A_METHODS.GET_TASK, { id: taskId });
			const getRes = await server.handleRequest(getReq);
			const getBody = await getRes.json();
			expect(getBody.result.id).toBe(taskId);
		});

		it("returns error for non-existent task", async () => {
			const server = createTestServer();
			const req = jsonRpcRequest(A2A_METHODS.GET_TASK, { id: "nonexistent" });
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.TASK_NOT_FOUND);
		});

		it("respects historyLength parameter", async () => {
			const server = createTestServer();
			// Send message to create a task with history
			const msg = makeMessage("History test");
			const sendReq = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			const sendRes = await server.handleRequest(sendReq);
			const sendBody = await sendRes.json();
			const taskId = sendBody.result.id;

			// Get with historyLength=0
			const getReq = jsonRpcRequest(A2A_METHODS.GET_TASK, { id: taskId, historyLength: 0 });
			const getRes = await server.handleRequest(getReq);
			const getBody = await getRes.json();
			expect(getBody.result.history).toEqual([]);
		});
	});

	describe("tasks/cancel", () => {
		it("cancels a working task", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: {
					onMessage: async (message) =>
						makeTask({
							status: { code: "working" },
							history: [message],
						}),
				},
			});

			// Create a working task
			const msg = makeMessage("Cancel me");
			const sendReq = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			const sendRes = await server.handleRequest(sendReq);
			const sendBody = await sendRes.json();
			const taskId = sendBody.result.id;

			// Cancel it
			const cancelReq = jsonRpcRequest(A2A_METHODS.CANCEL_TASK, { id: taskId });
			const cancelRes = await server.handleRequest(cancelReq);
			const cancelBody = await cancelRes.json();
			expect(cancelBody.result.status.code).toBe("canceled");
		});

		it("rejects cancel for non-existent task", async () => {
			const server = createTestServer();
			const req = jsonRpcRequest(A2A_METHODS.CANCEL_TASK, { id: "nope" });
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.TASK_NOT_FOUND);
		});

		it("rejects cancel for already completed task", async () => {
			const server = createTestServer();
			// Create a completed task
			const msg = makeMessage("Done");
			const sendReq = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			const sendRes = await server.handleRequest(sendReq);
			const sendBody = await sendRes.json();

			// Try to cancel
			const cancelReq = jsonRpcRequest(A2A_METHODS.CANCEL_TASK, { id: sendBody.result.id });
			const cancelRes = await server.handleRequest(cancelReq);
			const cancelBody = await cancelRes.json();
			expect(cancelBody.error.code).toBe(A2A_ERROR_CODES.TASK_ALREADY_COMPLETED);
		});
	});

	describe("authentication", () => {
		it("allows requests when no authenticator is configured", async () => {
			const server = createTestServer();
			const msg = makeMessage("No auth");
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.result).toBeDefined();
		});

		it("rejects unauthenticated requests when authenticator returns null", async () => {
			const server = createTestServer({
				authenticate: async () => null,
			});
			const msg = makeMessage("Should fail");
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.AUTHENTICATION_REQUIRED);
		});

		it("allows authenticated requests", async () => {
			const server = createTestServer({
				authenticate: async (req) => {
					const auth = req.headers.get("Authorization");
					if (auth === "Bearer valid-token") return "agent-abc";
					return null;
				},
			});
			const msg = makeMessage("Authenticated");
			const req = new Request("https://agent.example.com/a2a", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: "Bearer valid-token",
				},
				body: JSON.stringify({
					jsonrpc: A2A_JSONRPC_VERSION,
					id: 1,
					method: A2A_METHODS.SEND_MESSAGE,
					params: { message: msg },
				}),
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.result).toBeDefined();
		});

		it("rejects invalid tokens", async () => {
			const server = createTestServer({
				authenticate: async () => null,
			});
			const msg = makeMessage("Bad token");
			const req = new Request("https://agent.example.com/a2a", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: "Bearer bad-token",
				},
				body: JSON.stringify({
					jsonrpc: A2A_JSONRPC_VERSION,
					id: 1,
					method: A2A_METHODS.SEND_MESSAGE,
					params: { message: msg },
				}),
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.AUTHENTICATION_REQUIRED);
		});
	});

	describe("audit trail", () => {
		it("calls onAudit for each request", async () => {
			const auditLog: A2AAuditEvent[] = [];
			const server = createTestServer({
				onAudit: async (event) => {
					auditLog.push(event);
				},
			});

			const msg = makeMessage("Audit me");
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			await server.handleRequest(req);

			expect(auditLog).toHaveLength(1);
			expect(auditLog[0]?.method).toBe(A2A_METHODS.SEND_MESSAGE);
			expect(auditLog[0]?.success).toBe(true);
			expect(auditLog[0]?.timestamp).toBeDefined();
		});

		it("includes agent ID in audit when authenticated", async () => {
			const auditLog: A2AAuditEvent[] = [];
			const server = createTestServer({
				authenticate: async () => "agent-xyz",
				onAudit: async (event) => {
					auditLog.push(event);
				},
			});

			const msg = makeMessage("Audit auth");
			const req = jsonRpcRequest(A2A_METHODS.SEND_MESSAGE, { message: msg });
			await server.handleRequest(req);

			expect(auditLog[0]?.agentId).toBe("agent-xyz");
		});

		it("logs failed requests in audit", async () => {
			const auditLog: A2AAuditEvent[] = [];
			const server = createTestServer({
				onAudit: async (event) => {
					auditLog.push(event);
				},
			});

			const req = jsonRpcRequest(A2A_METHODS.GET_TASK, { id: "missing" });
			await server.handleRequest(req);

			expect(auditLog).toHaveLength(1);
			expect(auditLog[0]?.success).toBe(false);
			expect(auditLog[0]?.error).toContain("not found");
		});
	});

	describe("error handling", () => {
		it("returns 405 for non-POST non-GET requests", async () => {
			const server = createTestServer();
			const req = new Request("https://agent.example.com/a2a", {
				method: "PUT",
			});
			const res = await server.handleRequest(req);
			expect(res.status).toBe(405);
		});

		it("returns parse error for invalid JSON", async () => {
			const server = createTestServer();
			const req = new Request("https://agent.example.com/a2a", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "not json{{{",
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.PARSE_ERROR);
		});

		it("returns invalid request for bad JSON-RPC envelope", async () => {
			const server = createTestServer();
			const req = new Request("https://agent.example.com/a2a", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ not: "jsonrpc" }),
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.INVALID_REQUEST);
		});

		it("returns method not found for unknown methods", async () => {
			const server = createTestServer();
			const req = jsonRpcRequest("unknown/method", {});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.METHOD_NOT_FOUND);
		});

		it("returns streaming not supported when handler is missing", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: {
					onMessage: async () => makeTask(),
					// No onMessageStream
				},
			});
			const msg = makeMessage("Stream me");
			const req = jsonRpcRequest(A2A_METHODS.SEND_STREAMING_MESSAGE, {
				message: msg,
			});
			const res = await server.handleRequest(req);
			const body = await res.json();
			expect(body.error.code).toBe(A2A_ERROR_CODES.METHOD_NOT_FOUND);
		});
	});
});

// ─── A2A Client ──────────────────────────────────────────────────────────────

describe("A2A Client", () => {
	// Create a mock fetch that delegates to a local A2A server
	function createMockFetch(server: ReturnType<typeof createA2AServer>) {
		return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const method = init?.method ?? (input instanceof Request ? input.method : "GET");
			const headers =
				init?.headers ??
				(input instanceof Request ? Object.fromEntries(input.headers.entries()) : {});
			const body = init?.body ?? (input instanceof Request ? await input.text() : undefined);

			const request = new Request(url, {
				method,
				headers: headers as HeadersInit,
				body: body as string | undefined,
			});

			return server.handleRequest(request);
		};
	}

	describe("discover", () => {
		it("discovers an agent card from well-known URL", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: { onMessage: async () => makeTask() },
			});
			const mockFetch = createMockFetch(server);

			const client = createA2AClient({
				agent: "https://agent.example.com",
				fetch: mockFetch,
			});

			const result = await client.discover();
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.name).toBe("Test Agent");
			}
		});

		it("returns cached card if agent was passed as a card", async () => {
			const card = makeAgentCard();
			const client = createA2AClient({ agent: card });

			const result = await client.discover();
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.id).toBe(card.id);
			}
		});
	});

	describe("sendMessage", () => {
		it("sends a message and gets a task back", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: {
					onMessage: async (msg) =>
						makeTask({
							history: [msg],
						}),
				},
			});
			const mockFetch = createMockFetch(server);

			const client = createA2AClient({
				agent: card,
				fetch: mockFetch,
			});

			const result = await client.sendMessage({
				message: makeMessage("Hello from client"),
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.status.code).toBe("completed");
			}
		});
	});

	describe("getTask", () => {
		it("retrieves a task by ID", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: { onMessage: async () => makeTask() },
			});
			const mockFetch = createMockFetch(server);

			const client = createA2AClient({
				agent: card,
				fetch: mockFetch,
			});

			// Create a task first
			const sendResult = await client.sendMessage({
				message: makeMessage("Get me later"),
			});
			expect(sendResult.success).toBe(true);
			if (!sendResult.success) return;

			// Retrieve it
			const getResult = await client.getTask({ id: sendResult.data.id });
			expect(getResult.success).toBe(true);
			if (getResult.success) {
				expect(getResult.data.id).toBe(sendResult.data.id);
			}
		});
	});

	describe("cancelTask", () => {
		it("cancels a task", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: {
					onMessage: async () => makeTask({ status: { code: "working" } }),
				},
			});
			const mockFetch = createMockFetch(server);

			const client = createA2AClient({
				agent: card,
				fetch: mockFetch,
			});

			const sendResult = await client.sendMessage({
				message: makeMessage("Cancel me"),
			});
			expect(sendResult.success).toBe(true);
			if (!sendResult.success) return;

			const cancelResult = await client.cancelTask({ id: sendResult.data.id });
			expect(cancelResult.success).toBe(true);
			if (cancelResult.success) {
				expect(cancelResult.data.status.code).toBe("canceled");
			}
		});
	});

	describe("error handling", () => {
		it("handles agent not found (discovery fails)", async () => {
			const mockFetch = async (): Promise<Response> => {
				return new Response("Not Found", { status: 404 });
			};

			const client = createA2AClient({
				agent: "https://nonexistent.example.com",
				fetch: mockFetch,
			});

			const result = await client.discover();
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("A2A_DISCOVERY_FAILED");
			}
		});

		it("handles network errors", async () => {
			const mockFetch = async (): Promise<Response> => {
				throw new Error("Network error");
			};

			const client = createA2AClient({
				agent: "https://down.example.com",
				fetch: mockFetch,
			});

			const result = await client.discover();
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.message).toContain("Network error");
			}
		});

		it("handles JSON-RPC errors from server", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: { onMessage: async () => makeTask() },
			});
			const mockFetch = createMockFetch(server);

			const client = createA2AClient({
				agent: card,
				fetch: mockFetch,
			});

			// Try to get a non-existent task
			const result = await client.getTask({ id: "nonexistent" });
			expect(result.success).toBe(false);
		});

		it("handles permission denied via authentication", async () => {
			const card = makeAgentCard();
			const server = createA2AServer({
				agentCard: card,
				handler: { onMessage: async () => makeTask() },
				authenticate: async () => null, // Always reject
			});
			const mockFetch = createMockFetch(server);

			const client = createA2AClient({
				agent: card,
				fetch: mockFetch,
			});

			const result = await client.sendMessage({
				message: makeMessage("Denied"),
			});
			expect(result.success).toBe(false);
		});
	});
});

// ─── Zod Schema Tests ────────────────────────────────────────────────────────

describe("A2A Zod Schemas", () => {
	it("validates text parts", () => {
		const result = A2APartSchema.safeParse({ type: "text", text: "hello" });
		expect(result.success).toBe(true);
	});

	it("validates file parts", () => {
		const result = A2APartSchema.safeParse({
			type: "file",
			fileUri: "https://example.com/file.pdf",
			mimeType: "application/pdf",
		});
		expect(result.success).toBe(true);
	});

	it("validates data parts", () => {
		const result = A2APartSchema.safeParse({
			type: "data",
			mimeType: "application/json",
			data: "eyJ0ZXN0IjogdHJ1ZX0=",
		});
		expect(result.success).toBe(true);
	});

	it("rejects invalid part types", () => {
		const result = A2APartSchema.safeParse({ type: "invalid", text: "x" });
		expect(result.success).toBe(false);
	});

	it("validates all task states", () => {
		const states = [
			"submitted",
			"working",
			"input-required",
			"completed",
			"failed",
			"canceled",
			"auth-required",
			"rejected",
		];
		for (const state of states) {
			expect(A2ATaskStateSchema.safeParse(state).success).toBe(true);
		}
	});

	it("rejects invalid task states", () => {
		expect(A2ATaskStateSchema.safeParse("running").success).toBe(false);
	});

	it("validates a complete message", () => {
		const msg = makeMessage("Test");
		const result = A2AMessageSchema.safeParse(msg);
		expect(result.success).toBe(true);
	});

	it("rejects a message with empty parts", () => {
		const msg = { ...makeMessage(), parts: [] };
		const result = A2AMessageSchema.safeParse(msg);
		expect(result.success).toBe(false);
	});
});
