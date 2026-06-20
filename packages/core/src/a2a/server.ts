/**
 * A2A JSON-RPC server for TheAuth.
 *
 * Creates a Web API Request/Response handler that implements the A2A
 * protocol's JSON-RPC endpoint. Handles message/send, tasks/get,
 * tasks/cancel, and message/stream (SSE). Authenticates callers through
 * TheAuth and logs every interaction to the audit trail.
 */

import type {
	A2AAuditEvent,
	A2AJsonRpcError,
	A2AJsonRpcResponse,
	A2AServerConfig,
	A2ATask,
	A2ATaskStore,
} from "./types.js";
import {
	A2A_ERROR_CODES,
	A2A_JSONRPC_VERSION,
	A2A_METHODS,
	A2A_WELL_KNOWN_PATH,
	A2ACancelTaskParamsSchema,
	A2AGetTaskParamsSchema,
	A2AJsonRpcRequestSchema,
	A2ASendMessageParamsSchema,
} from "./types.js";

// ─── In-memory task store (default) ──────────────────────────────────────────

function createInMemoryTaskStore(): A2ATaskStore {
	const tasks = new Map<string, A2ATask>();
	return {
		async get(taskId: string) {
			return tasks.get(taskId);
		},
		async set(taskId: string, task: A2ATask) {
			tasks.set(taskId, task);
		},
		async delete(taskId: string) {
			return tasks.delete(taskId);
		},
	};
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function jsonRpcError(id: string | number | null, error: A2AJsonRpcError): Response {
	const body: A2AJsonRpcResponse = {
		jsonrpc: A2A_JSONRPC_VERSION,
		id: id ?? 0,
		error,
	};
	return new Response(JSON.stringify(body), {
		status: 200, // JSON-RPC always returns 200
		headers: { "Content-Type": "application/json" },
	});
}

function jsonRpcSuccess(id: string | number, result: unknown): Response {
	const body: A2AJsonRpcResponse = {
		jsonrpc: A2A_JSONRPC_VERSION,
		id,
		result,
	};
	return new Response(JSON.stringify(body), {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});
}

// ─── Create A2A Server ───────────────────────────────────────────────────────

export interface A2AServer {
	/** Handle an incoming HTTP request (JSON-RPC or agent card discovery) */
	handleRequest: (request: Request) => Promise<Response>;
	/** Access the task store directly (for testing or admin) */
	taskStore: A2ATaskStore;
}

/**
 * Create an A2A-compliant JSON-RPC server.
 *
 * The returned `handleRequest` function accepts standard Web API Request
 * objects and returns Response objects. Mount it at whatever path you
 * prefer; it also handles `/.well-known/agent.json` for agent card
 * discovery.
 *
 * @example
 * ```typescript
 * const server = createA2AServer({
 *   agentCard: myCard,
 *   handler: {
 *     onMessage: async (msg) => ({ id: '...', contextId: '...', status: { code: 'completed' }, ... }),
 *   },
 *   authenticate: async (req) => verifyToken(req),
 * });
 *
 * // In your HTTP framework:
 * app.all('/a2a', (req) => server.handleRequest(req));
 * ```
 */
export function createA2AServer(config: A2AServerConfig): A2AServer {
	const taskStore = config.taskStore ?? createInMemoryTaskStore();

	async function audit(event: Omit<A2AAuditEvent, "timestamp">): Promise<void> {
		if (config.onAudit) {
			await config.onAudit({
				...event,
				timestamp: new Date().toISOString(),
			});
		}
	}

	async function authenticate(
		request: Request,
	): Promise<{ agentId: string | null; error: Response | null }> {
		if (!config.authenticate) {
			return { agentId: null, error: null };
		}

		const agentId = await config.authenticate(request);
		if (agentId === null) {
			return {
				agentId: null,
				error: jsonRpcError(0, {
					code: A2A_ERROR_CODES.AUTHENTICATION_REQUIRED,
					message: "Authentication required",
				}),
			};
		}

		return { agentId, error: null };
	}

	async function handleSendMessage(
		id: string | number,
		params: unknown,
		agentId: string | null,
	): Promise<Response> {
		const parsed = A2ASendMessageParamsSchema.safeParse(params);
		if (!parsed.success) {
			await audit({
				method: A2A_METHODS.SEND_MESSAGE,
				agentId,
				success: false,
				error: "Invalid params",
			});
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.INVALID_PARAMS,
				message: `Invalid params: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
			});
		}

		try {
			const task = await config.handler.onMessage(parsed.data.message, parsed.data.configuration);

			await taskStore.set(task.id, task);
			await audit({
				method: A2A_METHODS.SEND_MESSAGE,
				agentId,
				taskId: task.id,
				success: true,
			});

			return jsonRpcSuccess(id, task);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Internal error";
			await audit({
				method: A2A_METHODS.SEND_MESSAGE,
				agentId,
				success: false,
				error: message,
			});
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.INTERNAL_ERROR,
				message,
			});
		}
	}

	async function handleGetTask(
		id: string | number,
		params: unknown,
		agentId: string | null,
	): Promise<Response> {
		const parsed = A2AGetTaskParamsSchema.safeParse(params);
		if (!parsed.success) {
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.INVALID_PARAMS,
				message: "Invalid params: id is required",
			});
		}

		const task = await taskStore.get(parsed.data.id);
		if (!task) {
			await audit({
				method: A2A_METHODS.GET_TASK,
				agentId,
				taskId: parsed.data.id,
				success: false,
				error: "Task not found",
			});
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.TASK_NOT_FOUND,
				message: `Task ${parsed.data.id} not found`,
			});
		}

		// Trim history if historyLength specified
		let result = task;
		if (parsed.data.historyLength !== undefined && task.history) {
			const len = parsed.data.historyLength;
			result = {
				...task,
				history: len === 0 ? [] : task.history.slice(-len),
			};
		}

		await audit({
			method: A2A_METHODS.GET_TASK,
			agentId,
			taskId: task.id,
			success: true,
		});

		return jsonRpcSuccess(id, result);
	}

	async function handleCancelTask(
		id: string | number,
		params: unknown,
		agentId: string | null,
	): Promise<Response> {
		const parsed = A2ACancelTaskParamsSchema.safeParse(params);
		if (!parsed.success) {
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.INVALID_PARAMS,
				message: "Invalid params: id is required",
			});
		}

		const existing = await taskStore.get(parsed.data.id);
		if (!existing) {
			await audit({
				method: A2A_METHODS.CANCEL_TASK,
				agentId,
				taskId: parsed.data.id,
				success: false,
				error: "Task not found",
			});
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.TASK_NOT_FOUND,
				message: `Task ${parsed.data.id} not found`,
			});
		}

		// Already in a terminal state
		if (
			existing.status.code === "completed" ||
			existing.status.code === "failed" ||
			existing.status.code === "canceled"
		) {
			await audit({
				method: A2A_METHODS.CANCEL_TASK,
				agentId,
				taskId: existing.id,
				success: false,
				error: "Task already in terminal state",
			});
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.TASK_ALREADY_COMPLETED,
				message: `Task ${parsed.data.id} is already ${existing.status.code}`,
			});
		}

		if (config.handler.onCancel) {
			try {
				const canceled = await config.handler.onCancel(parsed.data.id);
				await taskStore.set(canceled.id, canceled);
				await audit({
					method: A2A_METHODS.CANCEL_TASK,
					agentId,
					taskId: canceled.id,
					success: true,
				});
				return jsonRpcSuccess(id, canceled);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Cancel failed";
				await audit({
					method: A2A_METHODS.CANCEL_TASK,
					agentId,
					taskId: parsed.data.id,
					success: false,
					error: message,
				});
				return jsonRpcError(id, {
					code: A2A_ERROR_CODES.INTERNAL_ERROR,
					message,
				});
			}
		}

		// Default cancellation
		const canceled: A2ATask = {
			...existing,
			status: { code: "canceled", message: "Canceled by client" },
			updatedAt: new Date().toISOString(),
		};
		await taskStore.set(canceled.id, canceled);
		await audit({
			method: A2A_METHODS.CANCEL_TASK,
			agentId,
			taskId: canceled.id,
			success: true,
		});
		return jsonRpcSuccess(id, canceled);
	}

	function handleStreamingMessage(
		id: string | number,
		params: unknown,
		agentId: string | null,
	): Response {
		if (!config.handler.onMessageStream) {
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.METHOD_NOT_FOUND,
				message: "Streaming not supported by this agent",
			});
		}

		const parsed = A2ASendMessageParamsSchema.safeParse(params);
		if (!parsed.success) {
			return jsonRpcError(id, {
				code: A2A_ERROR_CODES.INVALID_PARAMS,
				message: "Invalid params",
			});
		}

		const stream = config.handler.onMessageStream(parsed.data.message, parsed.data.configuration);

		const encoder = new TextEncoder();
		const readable = new ReadableStream({
			async start(controller) {
				try {
					for await (const event of stream) {
						const data = JSON.stringify(event);
						controller.enqueue(encoder.encode(`data: ${data}\n\n`));
					}
					controller.enqueue(encoder.encode("data: [DONE]\n\n"));
					controller.close();
				} catch (err) {
					const errorData = JSON.stringify({
						type: "error",
						error: {
							code: A2A_ERROR_CODES.INTERNAL_ERROR,
							message: err instanceof Error ? err.message : "Stream error",
						},
					});
					controller.enqueue(encoder.encode(`data: ${errorData}\n\n`));
					controller.close();
				}
				// Fire-and-forget audit
				void audit({
					method: A2A_METHODS.SEND_STREAMING_MESSAGE,
					agentId,
					success: true,
				});
			},
		});

		return new Response(readable, {
			status: 200,
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-cache",
				Connection: "keep-alive",
			},
		});
	}

	async function handleRequest(request: Request): Promise<Response> {
		const url = new URL(request.url);

		// Agent Card discovery
		if (request.method === "GET" && url.pathname.endsWith(A2A_WELL_KNOWN_PATH)) {
			return new Response(JSON.stringify(config.agentCard), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		// Only POST for JSON-RPC
		if (request.method !== "POST") {
			return new Response("Method Not Allowed", { status: 405 });
		}

		// Authenticate
		const auth = await authenticate(request);
		if (auth.error) return auth.error;
		const agentId = auth.agentId;

		// Parse JSON-RPC envelope
		let body: unknown;
		try {
			body = await request.json();
		} catch {
			return jsonRpcError(null, {
				code: A2A_ERROR_CODES.PARSE_ERROR,
				message: "Invalid JSON",
			});
		}

		const envelope = A2AJsonRpcRequestSchema.safeParse(body);
		if (!envelope.success) {
			return jsonRpcError(null, {
				code: A2A_ERROR_CODES.INVALID_REQUEST,
				message: "Invalid JSON-RPC request",
			});
		}

		const { id: reqId, method, params } = envelope.data;

		switch (method) {
			case A2A_METHODS.SEND_MESSAGE:
				return handleSendMessage(reqId, params, agentId);

			case A2A_METHODS.GET_TASK:
				return handleGetTask(reqId, params, agentId);

			case A2A_METHODS.CANCEL_TASK:
				return handleCancelTask(reqId, params, agentId);

			case A2A_METHODS.SEND_STREAMING_MESSAGE:
				return handleStreamingMessage(reqId, params, agentId);

			default:
				await audit({
					method,
					agentId,
					success: false,
					error: "Method not found",
				});
				return jsonRpcError(reqId, {
					code: A2A_ERROR_CODES.METHOD_NOT_FOUND,
					message: `Unknown method: ${method}`,
				});
		}
	}

	return { handleRequest, taskStore };
}
