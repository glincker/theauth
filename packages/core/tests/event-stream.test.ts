import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { EventStreamModule, StreamEvent } from "../src/auth/event-stream.js";
import { createEventStreamModule, EVENT_TYPES } from "../src/auth/event-stream.js";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function createTestDb() {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: false,
			tokenExpiry: "24h",
		},
	});
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return theauth.db;
}

function makeEvent(overrides: Partial<StreamEvent> = {}): StreamEvent {
	return {
		id: `evt-${Math.random().toString(36).slice(2)}`,
		type: "audit",
		timestamp: new Date(),
		data: { action: "test" },
		...overrides,
	};
}

function makeSseRequest(
	overrides: {
		path?: string;
		headers?: Record<string, string>;
		searchParams?: Record<string, string>;
	} = {},
): Request {
	const path = overrides.path ?? "/api/theauth/events/stream";
	const url = new URL(`http://localhost${path}`);
	for (const [k, v] of Object.entries(overrides.searchParams ?? {})) {
		url.searchParams.set(k, v);
	}
	return new Request(url.toString(), {
		method: "GET",
		headers: {
			accept: "text/event-stream",
			...overrides.headers,
		},
	});
}

/** Collect all chunks emitted from a Response's readable stream until it closes. */
async function drainStream(response: Response, timeoutMs = 200): Promise<string> {
	const reader = response.body!.getReader();
	const decoder = new TextDecoder();
	let result = "";
	const timeout = new Promise<void>((resolve) => setTimeout(resolve, timeoutMs));

	while (true) {
		const race = await Promise.race([
			reader.read().then((chunk) => ({ done: chunk.done, chunk })),
			timeout.then(() => ({ done: true, chunk: { done: true, value: undefined } })),
		]);
		if (race.done) break;
		if (race.chunk.value) {
			result += decoder.decode(race.chunk.value);
		}
	}
	reader.cancel();
	return result;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("event stream: response headers", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;
	let stream: EventStreamModule;

	beforeEach(async () => {
		db = await createTestDb();
		stream = createEventStreamModule({ db, requireAuth: false });
	});

	afterEach(() => {
		stream.close();
	});

	it("returns text/event-stream content type", () => {
		const res = stream.handleRequest(makeSseRequest());
		expect(res).not.toBeNull();
		expect(res!.headers.get("content-type")).toBe("text/event-stream");
	});

	it("returns no-cache cache-control", () => {
		const res = stream.handleRequest(makeSseRequest());
		expect(res!.headers.get("cache-control")).toContain("no-cache");
	});

	it("returns keep-alive connection header", () => {
		const res = stream.handleRequest(makeSseRequest());
		expect(res!.headers.get("connection")).toBe("keep-alive");
	});

	it("returns x-accel-buffering no to disable nginx buffering", () => {
		const res = stream.handleRequest(makeSseRequest());
		expect(res!.headers.get("x-accel-buffering")).toBe("no");
	});

	it("returns 200 status code", () => {
		const res = stream.handleRequest(makeSseRequest());
		expect(res!.status).toBe(200);
	});
});

describe("event stream: request matching", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;
	let stream: EventStreamModule;

	beforeEach(async () => {
		db = await createTestDb();
		stream = createEventStreamModule({ db, requireAuth: false });
	});

	afterEach(() => {
		stream.close();
	});

	it("returns null for non-SSE requests (missing accept header)", () => {
		const req = new Request("http://localhost/api/theauth/events/stream", {
			method: "GET",
		});
		expect(stream.handleRequest(req)).toBeNull();
	});

	it("returns null for wrong path", () => {
		const req = makeSseRequest({ path: "/api/theauth/other" });
		expect(stream.handleRequest(req)).toBeNull();
	});

	it("returns null for POST requests", () => {
		const req = new Request("http://localhost/api/theauth/events/stream", {
			method: "POST",
			headers: { accept: "text/event-stream" },
		});
		expect(stream.handleRequest(req)).toBeNull();
	});

	it("handles requests to exact /events/stream path", () => {
		const res = stream.handleRequest(makeSseRequest());
		expect(res).not.toBeNull();
	});
});

describe("event stream: auth", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("rejects unauthenticated when requireAuth is true and no token provided", async () => {
		const stream = createEventStreamModule({ db, requireAuth: true });
		const res = stream.handleRequest(makeSseRequest());
		expect(res).not.toBeNull();
		// The stream sends an error event then closes
		const body = await drainStream(res!);
		expect(body).toContain("UNAUTHORIZED");
		stream.close();
	});

	it("accepts request with token in Authorization header when requireAuth is true", async () => {
		const stream = createEventStreamModule({
			db,
			requireAuth: true,
			validateToken: async (t) => (t === "valid-token" ? "user-1" : null),
		});
		const res = stream.handleRequest(
			makeSseRequest({ headers: { authorization: "Bearer valid-token" } }),
		);
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		stream.close();
	});

	it("accepts request with token in query param", async () => {
		const stream = createEventStreamModule({
			db,
			requireAuth: true,
			validateToken: async (t) => (t === "valid-token" ? "user-1" : null),
		});
		const res = stream.handleRequest(makeSseRequest({ searchParams: { token: "valid-token" } }));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		stream.close();
	});

	it("sends UNAUTHORIZED error event for invalid token", async () => {
		const stream = createEventStreamModule({
			db,
			requireAuth: true,
			validateToken: async () => null,
		});
		const res = stream.handleRequest(
			makeSseRequest({ headers: { authorization: "Bearer bad-token" } }),
		);
		const body = await drainStream(res!);
		expect(body).toContain("UNAUTHORIZED");
		stream.close();
	});

	it("skips auth checks when requireAuth is false", () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		const res = stream.handleRequest(makeSseRequest());
		expect(res!.status).toBe(200);
		stream.close();
	});
});

describe("event stream: connection count", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("starts at zero", () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		expect(stream.getConnectionCount()).toBe(0);
		stream.close();
	});

	it("increments when a client connects (after async setup)", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		stream.handleRequest(makeSseRequest());
		// Wait for async start callback
		await new Promise<void>((r) => setTimeout(r, 20));
		expect(stream.getConnectionCount()).toBe(1);
		stream.close();
	});

	it("returns zero after close()", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));
		stream.close();
		expect(stream.getConnectionCount()).toBe(0);
	});

	it("enforces maxConnections limit", async () => {
		const stream = createEventStreamModule({
			db,
			requireAuth: false,
			maxConnections: 2,
		});
		stream.handleRequest(makeSseRequest());
		stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));
		const res = stream.handleRequest(makeSseRequest());
		expect(res!.status).toBe(503);
		stream.close();
	});

	it("multiple clients connect independently", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		stream.handleRequest(makeSseRequest());
		stream.handleRequest(makeSseRequest());
		stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));
		expect(stream.getConnectionCount()).toBe(3);
		stream.close();
	});
});

describe("event stream: event emission", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;
	let stream: EventStreamModule;

	beforeEach(async () => {
		db = await createTestDb();
		stream = createEventStreamModule({ db, requireAuth: false });
	});

	afterEach(() => {
		stream.close();
	});

	it("emit does not throw when no clients connected", () => {
		expect(() => stream.emit(makeEvent())).not.toThrow();
	});

	it("emit sends event data to connected client", async () => {
		const response = stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));

		const evt = makeEvent({ id: "test-evt-1", type: "audit", data: { foo: "bar" } });
		stream.emit(evt);

		await new Promise<void>((r) => setTimeout(r, 20));
		const body = await drainStream(response!);

		expect(body).toContain("test-evt-1");
		expect(body).toContain("audit");
		expect(body).toContain("bar");
	});

	it("includes connected event on initial connection", async () => {
		const response = stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));
		const body = await drainStream(response!, 100);
		expect(body).toContain("connected");
		expect(body).toContain("clientId");
	});

	it("multiple clients all receive same event", async () => {
		const resp1 = stream.handleRequest(makeSseRequest());
		const resp2 = stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));

		const evt = makeEvent({ id: "broadcast-evt", type: "agent.created", data: {} });
		stream.emit(evt);

		await new Promise<void>((r) => setTimeout(r, 20));
		const [body1, body2] = await Promise.all([drainStream(resp1!), drainStream(resp2!)]);

		expect(body1).toContain("broadcast-evt");
		expect(body2).toContain("broadcast-evt");
	});
});

describe("event stream: type filtering", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("delivers events when no type filter set", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		const resp = stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));

		stream.emit(makeEvent({ id: "e1", type: "audit" }));
		stream.emit(makeEvent({ id: "e2", type: "agent.created" }));
		await new Promise<void>((r) => setTimeout(r, 20));

		const body = await drainStream(resp!);
		expect(body).toContain("e1");
		expect(body).toContain("e2");
		stream.close();
	});

	it("filters events by types query param", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		const resp = stream.handleRequest(makeSseRequest({ searchParams: { types: "agent.created" } }));
		await new Promise<void>((r) => setTimeout(r, 20));

		stream.emit(makeEvent({ id: "audit-evt", type: "audit" }));
		stream.emit(makeEvent({ id: "agent-evt", type: "agent.created" }));
		await new Promise<void>((r) => setTimeout(r, 20));

		const body = await drainStream(resp!);
		expect(body).toContain("agent-evt");
		expect(body).not.toContain("audit-evt");
		stream.close();
	});

	it("filters events by multiple types in query param", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		const resp = stream.handleRequest(
			makeSseRequest({ searchParams: { types: "audit,agent.revoked" } }),
		);
		await new Promise<void>((r) => setTimeout(r, 20));

		stream.emit(makeEvent({ id: "audit-e", type: "audit" }));
		stream.emit(makeEvent({ id: "revoke-e", type: "agent.revoked" }));
		stream.emit(makeEvent({ id: "create-e", type: "agent.created" }));
		await new Promise<void>((r) => setTimeout(r, 20));

		const body = await drainStream(resp!);
		expect(body).toContain("audit-e");
		expect(body).toContain("revoke-e");
		expect(body).not.toContain("create-e");
		stream.close();
	});

	it("ignores unknown type values in filter", async () => {
		const stream = createEventStreamModule({ db, requireAuth: false });
		// unknown types should be stripped — with no valid types remaining, no filter is applied
		const resp = stream.handleRequest(
			makeSseRequest({ searchParams: { types: "audit,invalid-type" } }),
		);
		await new Promise<void>((r) => setTimeout(r, 20));

		stream.emit(makeEvent({ id: "a-e", type: "audit" }));
		await new Promise<void>((r) => setTimeout(r, 20));

		const body = await drainStream(resp!);
		expect(body).toContain("a-e");
		stream.close();
	});

	it("module-level eventTypes config restricts all clients", async () => {
		const stream = createEventStreamModule({
			db,
			requireAuth: false,
			eventTypes: ["agent.created"],
		});
		const resp = stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));

		stream.emit(makeEvent({ id: "audit-only", type: "audit" }));
		stream.emit(makeEvent({ id: "agent-only", type: "agent.created" }));
		await new Promise<void>((r) => setTimeout(r, 20));

		const body = await drainStream(resp!);
		expect(body).toContain("agent-only");
		expect(body).not.toContain("audit-only");
		stream.close();
	});
});

describe("event stream: replay", () => {
	let db: Awaited<ReturnType<typeof createTestDb>>;
	let stream: EventStreamModule;

	beforeEach(async () => {
		db = await createTestDb();
		stream = createEventStreamModule({ db, requireAuth: false });
	});

	afterEach(() => {
		stream.close();
	});

	it("replay returns empty array when no events exist", async () => {
		const result = await stream.replay(new Date("2020-01-01"));
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data).toHaveLength(0);
		}
	});

	it("replay returns persisted events since the given date", async () => {
		const past = new Date("2020-01-01");
		const evt = makeEvent({ id: "replay-test", type: "audit" });
		stream.emit(evt);

		// Wait for persistence
		await new Promise<void>((r) => setTimeout(r, 30));

		const result = await stream.replay(past);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.some((e) => e.id === "replay-test")).toBe(true);
		}
	});

	it("replay filters by type", async () => {
		stream.emit(makeEvent({ id: "r-audit", type: "audit" }));
		stream.emit(makeEvent({ id: "r-agent", type: "agent.created" }));
		await new Promise<void>((r) => setTimeout(r, 30));

		const result = await stream.replay(new Date("2020-01-01"), ["agent.created"]);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.some((e) => e.id === "r-agent")).toBe(true);
			expect(result.data.some((e) => e.id === "r-audit")).toBe(false);
		}
	});

	it("replay excludes events before since date", async () => {
		const old = makeEvent({ id: "old-evt", type: "audit", timestamp: new Date("2019-01-01") });
		await db.insert(schema.streamEvents).values({
			id: old.id,
			type: old.type,
			timestamp: old.timestamp,
			data: old.data,
			agentId: null,
			userId: null,
		});

		const result = await stream.replay(new Date("2020-01-01"));
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.some((e) => e.id === "old-evt")).toBe(false);
		}
	});

	it("replay using since query param in SSE request", async () => {
		const evt = makeEvent({ id: "since-param-evt", type: "auth.signin" });
		stream.emit(evt);
		await new Promise<void>((r) => setTimeout(r, 30));

		const resp = stream.handleRequest(
			makeSseRequest({ searchParams: { since: "2020-01-01T00:00:00Z" } }),
		);
		await new Promise<void>((r) => setTimeout(r, 50));
		const body = await drainStream(resp!);

		expect(body).toContain("since-param-evt");
	});

	it("replay using Last-Event-ID header in SSE request", async () => {
		const evt = makeEvent({ id: "last-id-evt", type: "audit" });
		stream.emit(evt);
		await new Promise<void>((r) => setTimeout(r, 30));

		const resp = stream.handleRequest(
			makeSseRequest({ headers: { "last-event-id": "2020-01-01T00:00:00.000Z" } }),
		);
		await new Promise<void>((r) => setTimeout(r, 50));
		const body = await drainStream(resp!);

		expect(body).toContain("last-id-evt");
	});
});

describe("event stream: heartbeat", () => {
	it("sends heartbeat comments on interval", async () => {
		const db = await createTestDb();
		const stream = createEventStreamModule({
			db,
			requireAuth: false,
			heartbeatIntervalMs: 50,
		});

		const resp = stream.handleRequest(makeSseRequest());
		await new Promise<void>((r) => setTimeout(r, 20));

		// Wait for at least one heartbeat
		await new Promise<void>((r) => setTimeout(r, 80));
		const body = await drainStream(resp!, 30);

		expect(body).toContain(": heartbeat");
		stream.close();
	});
});

describe("event stream: persistence", () => {
	it("persists emitted events to database", async () => {
		const db = await createTestDb();
		const stream = createEventStreamModule({ db, requireAuth: false });

		const evt = makeEvent({ id: "persist-test", type: "agent.created" });
		stream.emit(evt);
		await new Promise<void>((r) => setTimeout(r, 30));

		const rows = await db
			.select()
			.from(schema.streamEvents)
			.where(require("drizzle-orm").eq(schema.streamEvents.id, "persist-test"));

		expect(rows).toHaveLength(1);
		expect(rows[0]?.type).toBe("agent.created");
		stream.close();
	});

	it("stores agentId and userId on persisted events", async () => {
		const db = await createTestDb();
		const stream = createEventStreamModule({ db, requireAuth: false });

		stream.emit(
			makeEvent({
				id: "agent-user-evt",
				type: "audit",
				agentId: "ag-1",
				userId: "user-1",
			}),
		);
		await new Promise<void>((r) => setTimeout(r, 30));

		const rows = await db
			.select()
			.from(schema.streamEvents)
			.where(require("drizzle-orm").eq(schema.streamEvents.id, "agent-user-evt"));

		expect(rows[0]?.agentId).toBe("ag-1");
		expect(rows[0]?.userId).toBe("user-1");
		stream.close();
	});
});

describe("event stream: EVENT_TYPES constant", () => {
	it("exports all expected event type strings", () => {
		expect(EVENT_TYPES).toContain("audit");
		expect(EVENT_TYPES).toContain("agent.created");
		expect(EVENT_TYPES).toContain("agent.revoked");
		expect(EVENT_TYPES).toContain("agent.rotated");
		expect(EVENT_TYPES).toContain("auth.signin");
		expect(EVENT_TYPES).toContain("auth.signout");
		expect(EVENT_TYPES).toContain("auth.failed");
		expect(EVENT_TYPES).toContain("delegation.created");
		expect(EVENT_TYPES).toContain("delegation.revoked");
		expect(EVENT_TYPES).toContain("budget.exceeded");
		expect(EVENT_TYPES).toContain("anomaly.detected");
		expect(EVENT_TYPES).toContain("cost.recorded");
	});

	it("has exactly the documented event types", () => {
		expect(EVENT_TYPES).toHaveLength(12);
	});
});
