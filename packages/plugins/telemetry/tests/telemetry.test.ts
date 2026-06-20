import { randomUUID } from "node:crypto";
import type { AgentIdentity, AuditEntry, DelegationChain } from "theauth";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TelemetrySpan } from "../src/exporter.js";
import { createTelemetryModule } from "../src/exporter.js";

function makeAuditEntry(overrides?: Partial<AuditEntry>): AuditEntry {
	const now = new Date();
	return {
		id: randomUUID(),
		agentId: "agent-1",
		userId: "user-1",
		action: "execute",
		resource: "mcp:github:create_issue",
		parameters: {},
		result: "allowed",
		durationMs: 42,
		timestamp: now,
		...overrides,
	};
}

function makeAgent(overrides?: Partial<AgentIdentity>): AgentIdentity {
	return {
		id: "agent-1",
		ownerId: "user-1",
		name: "test-agent",
		type: "autonomous",
		token: "",
		permissions: [],
		status: "active",
		expiresAt: null,
		createdAt: new Date(),
		updatedAt: new Date(),
		...overrides,
	};
}

function makeChain(overrides?: Partial<DelegationChain>): DelegationChain {
	return {
		id: randomUUID(),
		fromAgent: "agent-1",
		toAgent: "agent-2",
		permissions: [{ resource: "mcp:github", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 3600_000),
		depth: 1,
		createdAt: new Date(),
		...overrides,
	};
}

describe("createTelemetryModule", () => {
	let spans: TelemetrySpan[];
	let onSpan: (span: TelemetrySpan) => void;

	beforeEach(() => {
		spans = [];
		onSpan = vi.fn((span: TelemetrySpan) => {
			spans.push(span);
		});
	});

	describe("emitAuthorizeSpan", () => {
		it("emits a span with the correct name and attributes", () => {
			const telemetry = createTelemetryModule({ onSpan });
			const entry = makeAuditEntry({ result: "allowed", durationMs: 100 });

			telemetry.emitAuthorizeSpan(entry);

			expect(spans).toHaveLength(1);
			const span = spans[0];
			expect(span).toBeDefined();
			if (!span) return;

			expect(span.name).toBe("kavach.authorize");
			expect(span.kind).toBe("internal");
			expect(span.status).toBe("ok");
			expect(span.attributes["kavach.agent.id"]).toBe("agent-1");
			expect(span.attributes["kavach.action"]).toBe("execute");
			expect(span.attributes["kavach.resource"]).toBe("mcp:github:create_issue");
			expect(span.attributes["kavach.result"]).toBe("allowed");
			expect(span.attributes["kavach.duration_ms"]).toBe(100);
			expect(span.attributes["kavach.user.id"]).toBe("user-1");
		});

		it("sets status to error when result is denied", () => {
			const telemetry = createTelemetryModule({ onSpan });
			const entry = makeAuditEntry({ result: "denied" });

			telemetry.emitAuthorizeSpan(entry);

			expect(spans[0]?.status).toBe("error");
		});

		it("uses custom service name in attributes", () => {
			const telemetry = createTelemetryModule({ onSpan, serviceName: "my-service" });
			telemetry.emitAuthorizeSpan(makeAuditEntry());

			expect(spans[0]?.attributes["service.name"]).toBe("my-service");
		});

		it("defaults service name to theauth", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitAuthorizeSpan(makeAuditEntry());

			expect(spans[0]?.attributes["service.name"]).toBe("theauth");
		});

		it("includes tokensCost when present", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitAuthorizeSpan(makeAuditEntry({ tokensCost: 1500 }));

			expect(spans[0]?.attributes["kavach.tokens_cost"]).toBe(1500);
		});

		it("omits arguments by default (privacy)", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitAuthorizeSpan(makeAuditEntry({ parameters: { repo: "my-repo" } }));

			expect(spans[0]?.attributes["kavach.arguments"]).toBeUndefined();
		});

		it("includes arguments when includeArguments is true", () => {
			const telemetry = createTelemetryModule({ onSpan, includeArguments: true });
			telemetry.emitAuthorizeSpan(makeAuditEntry({ parameters: { repo: "my-repo" } }));

			expect(spans[0]?.attributes["kavach.arguments"]).toBe('{"repo":"my-repo"}');
		});

		it("generates unique trace and span IDs", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitAuthorizeSpan(makeAuditEntry());
			telemetry.emitAuthorizeSpan(makeAuditEntry());

			expect(spans[0]?.spanId).not.toBe(spans[1]?.spanId);
			expect(spans[0]?.traceId).not.toBe(spans[1]?.traceId);
		});

		it("does not call onSpan when not configured", () => {
			const telemetry = createTelemetryModule({});
			expect(() => telemetry.emitAuthorizeSpan(makeAuditEntry())).not.toThrow();
		});
	});

	describe("emitDelegationSpan", () => {
		it("emits a span for chain creation", () => {
			const telemetry = createTelemetryModule({ onSpan });
			const chain = makeChain();

			telemetry.emitDelegationSpan(chain, "create");

			expect(spans).toHaveLength(1);
			const span = spans[0];
			expect(span?.name).toBe("kavach.delegation.create");
			expect(span?.attributes["kavach.delegation.id"]).toBe(chain.id);
			expect(span?.attributes["kavach.delegation.from_agent"]).toBe("agent-1");
			expect(span?.attributes["kavach.delegation.to_agent"]).toBe("agent-2");
			expect(span?.attributes["kavach.delegation.depth"]).toBe(1);
			expect(span?.attributes["kavach.delegation.action"]).toBe("create");
			expect(span?.status).toBe("ok");
		});

		it("emits a span for chain revocation", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitDelegationSpan(makeChain(), "revoke");

			expect(spans[0]?.name).toBe("kavach.delegation.revoke");
		});
	});

	describe("emitAgentSpan", () => {
		it("emits a span for agent creation", () => {
			const telemetry = createTelemetryModule({ onSpan });
			const agent = makeAgent();

			telemetry.emitAgentSpan(agent, "create");

			expect(spans).toHaveLength(1);
			const span = spans[0];
			expect(span?.name).toBe("kavach.agent.create");
			expect(span?.attributes["kavach.agent.id"]).toBe("agent-1");
			expect(span?.attributes["kavach.agent.name"]).toBe("test-agent");
			expect(span?.attributes["kavach.agent.type"]).toBe("autonomous");
			expect(span?.attributes["kavach.user.id"]).toBe("user-1");
			expect(span?.status).toBe("ok");
		});

		it("emits a span for agent revocation", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitAgentSpan(makeAgent(), "revoke");

			expect(spans[0]?.name).toBe("kavach.agent.revoke");
		});

		it("emits a span for token rotation", () => {
			const telemetry = createTelemetryModule({ onSpan });
			telemetry.emitAgentSpan(makeAgent(), "rotate");

			expect(spans[0]?.name).toBe("kavach.agent.rotate");
		});
	});
});
