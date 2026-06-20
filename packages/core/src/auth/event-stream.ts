/**
 * Real-time event streaming via Server-Sent Events (SSE) for TheAuth.
 *
 * Provides a persistent connection feed of audit events, agent lifecycle
 * changes, auth events, and anomalies. SOC teams and monitoring systems can
 * subscribe instead of polling the audit API or relying solely on webhooks.
 *
 * Endpoint: GET /api/kavach/events/stream
 * Auth: Bearer token via Authorization header or `?token=` query param
 * Filtering: `?types=audit,agent.created`
 * Replay: `?since=2026-01-01T00:00:00Z` or Last-Event-ID header
 *
 * @example
 * ```typescript
 * const stream = createEventStreamModule({ db, requireAuth: true });
 *
 * // In your request handler
 * const response = stream.handleRequest(request);
 * if (response) return response;
 *
 * // Emit from anywhere in your app
 * stream.emit({
 *   id: crypto.generateId(),
 *   type: 'agent.created',
 *   timestamp: new Date(),
 *   data: { agentId: 'ag_123', name: 'my-agent' },
 * });
 * ```
 */

import { and, desc, gte, inArray } from "drizzle-orm";
import { z } from "zod";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { streamEvents } from "../db/schema.js";
import type { KavachError, Result } from "../mcp/types.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export const EVENT_TYPES = [
	"audit",
	"agent.created",
	"agent.revoked",
	"agent.rotated",
	"auth.signin",
	"auth.signout",
	"auth.failed",
	"delegation.created",
	"delegation.revoked",
	"budget.exceeded",
	"anomaly.detected",
	"cost.recorded",
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

export interface StreamEvent {
	id: string;
	type: EventType;
	timestamp: Date;
	data: Record<string, unknown>;
	agentId?: string;
	userId?: string;
}

export interface EventStreamConfig {
	db: Database;
	/** Maximum concurrent SSE connections (default: 100) */
	maxConnections?: number;
	/** Heartbeat interval in milliseconds (default: 30000) */
	heartbeatIntervalMs?: number;
	/** Restrict which event types this stream delivers (default: all) */
	eventTypes?: EventType[];
	/** Require a valid Bearer token to connect (default: true) */
	requireAuth?: boolean;
	/**
	 * Validate a Bearer token and return the subscriber ID (userId or agentId)
	 * on success, or null on failure.
	 *
	 * Only called when `requireAuth` is true. When omitted, any non-empty token
	 * is accepted and used as the subscriber ID.
	 */
	validateToken?: (token: string) => Promise<string | null>;
}

export interface EventStreamModule {
	/** Emit an event to all connected clients. */
	emit(event: StreamEvent): void;
	/** Handle an incoming HTTP request. Returns a Response or null when the request is not an SSE request. */
	handleRequest(request: Request): Response | null;
	/** Current number of active SSE connections. */
	getConnectionCount(): number;
	/** Replay persisted events since a timestamp, optionally filtered by type. */
	replay(since: Date, types?: EventType[]): Promise<Result<StreamEvent[]>>;
	/** Close all active connections and stop heartbeats. */
	close(): void;
}

// ─── Validation ───────────────────────────────────────────────────────────────

const eventTypeSchema = z.enum(EVENT_TYPES);

const queryParamsSchema = z.object({
	token: z.string().optional(),
	types: z.string().optional(),
	since: z.string().datetime({ offset: true }).optional(),
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ok<T>(data: T): Result<T> {
	return { success: true, data };
}

function fail(code: string, message: string): Result<never> {
	const error: KavachError = { code, message };
	return { success: false, error };
}

function parseEventTypes(raw: string): EventType[] {
	return raw
		.split(",")
		.map((s) => s.trim())
		.filter((s): s is EventType => eventTypeSchema.safeParse(s).success);
}

function formatSseEvent(event: StreamEvent): string {
	const data = JSON.stringify({
		id: event.id,
		type: event.type,
		timestamp: event.timestamp.toISOString(),
		data: event.data,
		...(event.agentId ? { agentId: event.agentId } : {}),
		...(event.userId ? { userId: event.userId } : {}),
	});
	return `id: ${event.id}\nevent: ${event.type}\ndata: ${data}\n\n`;
}

function extractToken(request: Request): string | null {
	const auth = request.headers.get("authorization");
	if (auth?.startsWith("Bearer ")) {
		return auth.slice(7).trim() || null;
	}
	const url = new URL(request.url);
	return url.searchParams.get("token");
}

function isSseRequest(request: Request): boolean {
	if (request.method !== "GET") return false;
	const url = new URL(request.url);
	if (!url.pathname.endsWith("/events/stream")) return false;
	const accept = request.headers.get("accept") ?? "";
	return accept.includes("text/event-stream");
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export function createEventStreamModule(config: EventStreamConfig): EventStreamModule {
	const {
		db,
		maxConnections = 100,
		heartbeatIntervalMs = 30_000,
		eventTypes: allowedTypes,
		requireAuth = true,
		validateToken,
	} = config;

	// Active client controllers — one per open SSE connection
	const clients = new Map<
		string,
		{ controller: ReadableStreamDefaultController<Uint8Array>; types: EventType[] | null }
	>();

	// Heartbeat timer — fired once, sends to all clients
	let heartbeatTimer: ReturnType<typeof setInterval> | null = null;

	function startHeartbeat(): void {
		if (heartbeatTimer !== null) return;
		heartbeatTimer = setInterval(() => {
			const heartbeat = new TextEncoder().encode(": heartbeat\n\n");
			for (const { controller } of clients.values()) {
				try {
					controller.enqueue(heartbeat);
				} catch {
					// Client disconnected — the cleanup runs in the cancel callback
				}
			}
		}, heartbeatIntervalMs);
	}

	function stopHeartbeat(): void {
		if (heartbeatTimer !== null) {
			clearInterval(heartbeatTimer);
			heartbeatTimer = null;
		}
	}

	function removeClient(id: string): void {
		clients.delete(id);
		if (clients.size === 0) {
			stopHeartbeat();
		}
	}

	function emit(event: StreamEvent): void {
		// Persist for replay
		void persistEvent(event);

		const encoded = new TextEncoder().encode(formatSseEvent(event));

		for (const [id, client] of clients.entries()) {
			// Apply per-connection type filter
			if (client.types !== null && !client.types.includes(event.type)) continue;
			// Apply module-level type filter
			if (allowedTypes && !allowedTypes.includes(event.type)) continue;

			try {
				client.controller.enqueue(encoded);
			} catch {
				removeClient(id);
			}
		}
	}

	async function persistEvent(event: StreamEvent): Promise<void> {
		try {
			await db.insert(streamEvents).values({
				id: event.id,
				type: event.type,
				timestamp: event.timestamp,
				data: event.data,
				agentId: event.agentId ?? null,
				userId: event.userId ?? null,
			});
		} catch {
			// Non-fatal — streaming continues even when persistence fails
		}
	}

	async function replay(since: Date, types?: EventType[]): Promise<Result<StreamEvent[]>> {
		try {
			const conditions = [gte(streamEvents.timestamp, since)];
			if (types && types.length > 0) {
				conditions.push(inArray(streamEvents.type, types));
			}

			const rows = await db
				.select()
				.from(streamEvents)
				.where(and(...conditions))
				.orderBy(desc(streamEvents.timestamp))
				.limit(1000);

			const events: StreamEvent[] = rows.map((row) => ({
				id: row.id,
				type: row.type as EventType,
				timestamp: row.timestamp,
				data: (row.data as Record<string, unknown>) ?? {},
				agentId: row.agentId ?? undefined,
				userId: row.userId ?? undefined,
			}));

			return ok(events);
		} catch (err) {
			return fail("REPLAY_FAILED", err instanceof Error ? err.message : "Failed to replay events");
		}
	}

	function handleRequest(request: Request): Response | null {
		if (!isSseRequest(request)) return null;

		// Reject when at max capacity
		if (clients.size >= maxConnections) {
			return new Response("Too many connections", { status: 503 });
		}

		// Parse query params
		const url = new URL(request.url);
		const rawParams: Record<string, string> = {};
		for (const [k, v] of url.searchParams.entries()) {
			rawParams[k] = v;
		}
		const parsed = queryParamsSchema.safeParse(rawParams);
		if (!parsed.success) {
			return new Response("Invalid query parameters", { status: 400 });
		}
		const params = parsed.data;

		// Async setup — we return the Response immediately and do auth inside the
		// ReadableStream start callback so the HTTP layer doesn't need to await.
		const clientId = generateId();

		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				// Auth then attach
				void (async () => {
					if (requireAuth) {
						const token = extractToken(request) ?? params.token ?? null;
						if (!token) {
							controller.enqueue(
								new TextEncoder().encode(
									`event: error\ndata: ${JSON.stringify({ code: "UNAUTHORIZED", message: "Bearer token required" })}\n\n`,
								),
							);
							controller.close();
							return;
						}

						if (validateToken) {
							const subject = await validateToken(token);
							if (!subject) {
								controller.enqueue(
									new TextEncoder().encode(
										`event: error\ndata: ${JSON.stringify({ code: "UNAUTHORIZED", message: "Invalid token" })}\n\n`,
									),
								);
								controller.close();
								return;
							}
						}
					}

					// Resolve per-connection type filter
					let connectionTypes: EventType[] | null = null;
					if (params.types) {
						const filtered = parseEventTypes(params.types);
						connectionTypes = filtered.length > 0 ? filtered : null;
					}

					clients.set(clientId, { controller, types: connectionTypes });
					startHeartbeat();

					// Send a connected confirmation
					controller.enqueue(
						new TextEncoder().encode(
							`event: connected\ndata: ${JSON.stringify({ clientId, timestamp: new Date().toISOString() })}\n\n`,
						),
					);

					// Replay missed events if requested
					const sinceRaw = params.since ?? request.headers.get("last-event-id") ?? null;
					if (sinceRaw) {
						const sinceDate = new Date(sinceRaw);
						if (!Number.isNaN(sinceDate.getTime())) {
							const replayTypes = connectionTypes ?? allowedTypes ?? undefined;
							const result = await replay(sinceDate, replayTypes);
							if (result.success) {
								// Oldest first so clients see events in order
								const ordered = [...result.data].reverse();
								for (const evt of ordered) {
									controller.enqueue(new TextEncoder().encode(formatSseEvent(evt)));
								}
							}
						}
					}
				})();
			},
			cancel() {
				removeClient(clientId);
			},
		});

		return new Response(stream, {
			status: 200,
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-cache, no-store, no-transform",
				Connection: "keep-alive",
				"X-Accel-Buffering": "no",
			},
		});
	}

	function getConnectionCount(): number {
		return clients.size;
	}

	function close(): void {
		stopHeartbeat();
		for (const [id, { controller }] of clients.entries()) {
			try {
				controller.close();
			} catch {
				// Already closed
			}
			clients.delete(id);
		}
	}

	return { emit, handleRequest, getConnectionCount, replay, close };
}
