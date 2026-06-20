/**
 * A2A client for TheAuth.
 *
 * Discovers remote agents via /.well-known/agent.json and communicates
 * with them through JSON-RPC over HTTP. Supports message send, task
 * retrieval, cancellation, and SSE streaming.
 */

import { generateId } from "../crypto/web-crypto.js";
import type {
	A2AAgentCard,
	A2ACancelTaskParams,
	A2AClient,
	A2AClientConfig,
	A2AGetTaskParams,
	A2AJsonRpcResponse,
	A2ASendMessageParams,
	A2AStreamEvent,
	A2ATask,
	Result,
} from "./types.js";
import {
	A2A_JSONRPC_VERSION,
	A2A_METHODS,
	A2A_WELL_KNOWN_PATH,
	A2AAgentCardSchema,
} from "./types.js";

// ─── Create A2A Client ──────────────────────────────────────────────────────

/**
 * Create an A2A client that can discover and call remote A2A agents.
 *
 * @example
 * ```typescript
 * const client = createA2AClient({
 *   agent: 'https://remote-agent.example.com',
 *   getAuthToken: () => kavach.issueToken({ agentId: myAgent.id }),
 * });
 *
 * const card = await client.discover();
 * const result = await client.sendMessage({
 *   message: { id: '1', role: 'user', parts: [{ type: 'text', text: 'Hello' }], createdAt: new Date().toISOString() },
 * });
 * ```
 */
export function createA2AClient(config: A2AClientConfig): A2AClient {
	const fetchFn = config.fetch ?? globalThis.fetch;
	const timeout = config.timeout ?? 30_000;

	let cachedCard: A2AAgentCard | undefined;

	// Resolve the base URL from the config
	function getBaseUrl(): string {
		if (typeof config.agent === "string") {
			return config.agent.replace(/\/$/, "");
		}
		return config.agent.url.replace(/\/$/, "");
	}

	// If the agent was passed as a card, use it directly
	if (typeof config.agent !== "string") {
		cachedCard = config.agent;
	}

	async function getAuthHeaders(): Promise<Record<string, string>> {
		if (!config.getAuthToken) return {};
		const token = await config.getAuthToken();
		return { Authorization: `Bearer ${token}` };
	}

	async function jsonRpcCall<R>(method: string, params: unknown): Promise<Result<R>> {
		const baseUrl = cachedCard?.url ?? getBaseUrl();
		const authHeaders = await getAuthHeaders();

		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeout);

		try {
			const response = await fetchFn(baseUrl, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					...authHeaders,
				},
				body: JSON.stringify({
					jsonrpc: A2A_JSONRPC_VERSION,
					id: generateId(),
					method,
					params,
				}),
				signal: controller.signal,
			});

			if (!response.ok) {
				return {
					success: false,
					error: {
						code: "A2A_HTTP_ERROR",
						message: `HTTP ${response.status}: ${response.statusText}`,
					},
				};
			}

			const body = (await response.json()) as A2AJsonRpcResponse<R>;

			if (body.error) {
				return {
					success: false,
					error: {
						code: `A2A_RPC_${body.error.code}`,
						message: body.error.message,
						details: body.error.data ? { data: body.error.data } : undefined,
					},
				};
			}

			return { success: true, data: body.result as R };
		} catch (err) {
			if (err instanceof DOMException && err.name === "AbortError") {
				return {
					success: false,
					error: {
						code: "A2A_TIMEOUT",
						message: `Request timed out after ${timeout}ms`,
					},
				};
			}
			return {
				success: false,
				error: {
					code: "A2A_REQUEST_FAILED",
					message: err instanceof Error ? err.message : "Request failed",
				},
			};
		} finally {
			clearTimeout(timer);
		}
	}

	async function discover(): Promise<Result<A2AAgentCard>> {
		if (cachedCard) {
			return { success: true, data: cachedCard };
		}

		const baseUrl = getBaseUrl();
		const url = `${baseUrl}${A2A_WELL_KNOWN_PATH}`;
		const authHeaders = await getAuthHeaders();

		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeout);

		try {
			const response = await fetchFn(url, {
				method: "GET",
				headers: authHeaders,
				signal: controller.signal,
			});

			if (!response.ok) {
				return {
					success: false,
					error: {
						code: "A2A_DISCOVERY_FAILED",
						message: `Discovery failed: HTTP ${response.status}`,
					},
				};
			}

			const body: unknown = await response.json();
			const parsed = A2AAgentCardSchema.safeParse(body);

			if (!parsed.success) {
				return {
					success: false,
					error: {
						code: "A2A_INVALID_AGENT_CARD",
						message: `Invalid agent card: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
					},
				};
			}

			cachedCard = parsed.data as A2AAgentCard;
			return { success: true, data: cachedCard };
		} catch (err) {
			return {
				success: false,
				error: {
					code: "A2A_DISCOVERY_FAILED",
					message: err instanceof Error ? err.message : "Discovery request failed",
				},
			};
		} finally {
			clearTimeout(timer);
		}
	}

	async function sendMessage(params: A2ASendMessageParams): Promise<Result<A2ATask>> {
		return jsonRpcCall<A2ATask>(A2A_METHODS.SEND_MESSAGE, params);
	}

	async function getTask(params: A2AGetTaskParams): Promise<Result<A2ATask>> {
		return jsonRpcCall<A2ATask>(A2A_METHODS.GET_TASK, params);
	}

	async function cancelTask(params: A2ACancelTaskParams): Promise<Result<A2ATask>> {
		return jsonRpcCall<A2ATask>(A2A_METHODS.CANCEL_TASK, params);
	}

	async function* sendStreamingMessage(
		params: A2ASendMessageParams,
	): AsyncIterable<A2AStreamEvent> {
		const baseUrl = cachedCard?.url ?? getBaseUrl();
		const authHeaders = await getAuthHeaders();

		const response = await fetchFn(baseUrl, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "text/event-stream",
				...authHeaders,
			},
			body: JSON.stringify({
				jsonrpc: A2A_JSONRPC_VERSION,
				id: generateId(),
				method: A2A_METHODS.SEND_STREAMING_MESSAGE,
				params,
			}),
		});

		if (!response.ok || !response.body) {
			throw new Error(`Streaming request failed: HTTP ${response.status}`);
		}

		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let buffer = "";

		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;

				buffer += decoder.decode(value, { stream: true });
				const lines = buffer.split("\n");
				buffer = lines.pop() ?? "";

				for (const line of lines) {
					if (line.startsWith("data: ")) {
						const data = line.slice(6).trim();
						if (data === "[DONE]") return;
						try {
							yield JSON.parse(data) as A2AStreamEvent;
						} catch {
							// Skip malformed SSE lines
						}
					}
				}
			}
		} finally {
			reader.releaseLock();
		}
	}

	return {
		discover,
		sendMessage,
		getTask,
		cancelTask,
		sendStreamingMessage,
	};
}
