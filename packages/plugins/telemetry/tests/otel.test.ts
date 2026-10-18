import { describe, expect, it } from "vitest";
import type { DecisionEventLike, OtelAttributes } from "../src/otel.js";
import { OTEL_NAMES, theauthOtel } from "../src/otel.js";

interface RecordedSpan {
	name: string;
	startTime?: number | Date;
	attributes?: OtelAttributes;
	events: Array<{ name: string; attributes?: OtelAttributes }>;
	status?: { code: number; message?: string };
	endTime?: number | Date;
}

function harness() {
	const spans: RecordedSpan[] = [];
	const counts: Array<{ name: string; value: number; attributes?: OtelAttributes }> = [];
	const records: Array<{ name: string; value: number; attributes?: OtelAttributes }> = [];
	const created: Array<{ kind: string; name: string; unit?: string }> = [];
	const tracer = {
		startSpan(name: string, options?: { startTime?: number | Date; attributes?: OtelAttributes }) {
			const span: RecordedSpan = { name, ...options, events: [] };
			spans.push(span);
			return {
				addEvent(eventName: string, attributes?: OtelAttributes) {
					span.events.push({ name: eventName, attributes });
				},
				setStatus(status: { code: number; message?: string }) {
					span.status = status;
				},
				end(endTime?: number | Date) {
					span.endTime = endTime;
				},
			};
		},
	};
	const meter = {
		createCounter(name: string, options?: { unit?: string }) {
			created.push({ kind: "counter", name, unit: options?.unit });
			return {
				add: (value: number, attributes?: OtelAttributes) =>
					counts.push({ name, value, attributes }),
			};
		},
		createHistogram(name: string, options?: { unit?: string }) {
			created.push({ kind: "histogram", name, unit: options?.unit });
			return {
				record: (value: number, attributes?: OtelAttributes) =>
					records.push({ name, value, attributes }),
			};
		},
	};
	return { spans, counts, records, created, tracer, meter };
}

function event(overrides: Partial<DecisionEventLike> = {}): DecisionEventLike {
	return {
		source: "authorize",
		agentId: "agent-1",
		ownerId: "user-1",
		action: "read",
		resource: "mcp:github:issues",
		decision: "deny",
		code: "no_permission",
		durationMs: 12,
		cacheHit: false,
		delegationDepth: 2,
		auditId: "audit-1",
		at: new Date("2026-10-17T10:00:00.000Z"),
		...overrides,
	};
}

describe("theauthOtel", () => {
	it("creates the counter and histogram with the documented names and units", () => {
		const h = harness();
		theauthOtel({ meter: h.meter });
		expect(h.created).toEqual([
			{ kind: "counter", name: "theauth.decisions", unit: "{decision}" },
			{ kind: "histogram", name: "theauth.decision.duration", unit: "ms" },
		]);
	});

	it("records metrics with decision, code and source only", () => {
		const h = harness();
		theauthOtel({ meter: h.meter }).observability.onDecision(event());
		const attrs = {
			"theauth.decision": "deny",
			"theauth.decision.code": "no_permission",
			"theauth.source": "authorize",
		};
		expect(h.counts).toEqual([{ name: OTEL_NAMES.decisionsCounter, value: 1, attributes: attrs }]);
		expect(h.records).toEqual([
			{ name: OTEL_NAMES.durationHistogram, value: 12, attributes: attrs },
		]);
	});

	it("emits a backdated span with the decision attributes", () => {
		const h = harness();
		theauthOtel({ tracer: h.tracer }).observability.onDecision(
			event({ guard: "pii", hookOutcome: "deny", hookMs: 3 }),
		);
		const span = h.spans[0];
		expect(span?.name).toBe("theauth.authorize");
		expect((span?.startTime as Date).toISOString()).toBe("2026-10-17T09:59:59.988Z");
		expect(span?.endTime).toEqual(new Date("2026-10-17T10:00:00.000Z"));
		expect(span?.attributes).toMatchObject({
			"theauth.decision": "deny",
			"theauth.decision.code": "no_permission",
			"theauth.agent.id": "agent-1",
			"theauth.delegation.depth": 2,
			"theauth.guard.name": "pii",
			"theauth.source": "authorize",
			"theauth.hook.outcome": "deny",
			"theauth.resource": "mcp:github:issues",
		});
		expect(span?.status).toBeUndefined();
		expect(span?.events).toEqual([]);
	});

	it("adds a span event and an error status for a hook timeout", () => {
		const h = harness();
		theauthOtel({ tracer: h.tracer }).observability.onDecision(
			event({ code: "hook_timeout", hookOutcome: "timeout", hookMs: 2000 }),
		);
		const span = h.spans[0];
		expect(span?.events[0]?.name).toBe("theauth.hook.timeout");
		expect(span?.events[0]?.attributes).toMatchObject({ "theauth.hook.duration": 2000 });
		expect(span?.status?.code).toBe(2);
	});

	it("marks fail_open with an event but no error status", () => {
		const h = harness();
		theauthOtel({ tracer: h.tracer }).observability.onDecision(
			event({ decision: "allow", code: "allowed", hookOutcome: "fail_open", hookMs: 50 }),
		);
		expect(h.spans[0]?.events[0]?.name).toBe("theauth.hook.fail_open");
		expect(h.spans[0]?.status).toBeUndefined();
	});

	it("names policy.evaluate spans separately and can omit the resource", () => {
		const h = harness();
		theauthOtel({ tracer: h.tracer, includeResource: false }).observability.onDecision(
			event({ source: "policy.evaluate" }),
		);
		expect(h.spans[0]?.name).toBe("theauth.policy.evaluate");
		expect(h.spans[0]?.attributes).not.toHaveProperty("theauth.resource");
	});

	it("works with neither tracer nor meter", () => {
		expect(() => theauthOtel().observability.onDecision(event())).not.toThrow();
	});
});
