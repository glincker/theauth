import { randomUUID } from "node:crypto";
import type { AgentIdentity, AuditEntry, DelegationChain } from "@glinr/theauth";

export interface TelemetrySpan {
	traceId: string;
	spanId: string;
	name: string;
	kind: "internal";
	startTime: string;
	endTime: string;
	attributes: Record<string, string | number | boolean>;
	status: "ok" | "error";
}

export interface TelemetryConfig {
	/** Called for every authorization event */
	onSpan?: (span: TelemetrySpan) => void;
	/** Service name for spans */
	serviceName?: string;
	/** Whether to include arguments in span attributes */
	includeArguments?: boolean;
}

function generateId(): string {
	// Generate a 16-byte hex string (standard for OTel trace/span IDs)
	return randomUUID().replace(/-/g, "").slice(0, 16);
}

/**
 * Create the telemetry module.
 *
 * Converts TheAuth events into OpenTelemetry-compatible span shapes and
 * delivers them via the user-supplied `onSpan` callback. No @opentelemetry
 * dependency — callers wire this into their own OTel SDK.
 *
 * @example
 * ```typescript
 * import { createTelemetryModule } from '@glinr/theauth-plugin-telemetry';
 *
 * const telemetry = createTelemetryModule({
 *   serviceName: 'my-agent-service',
 *   onSpan: (span) => tracer.startActiveSpan(span.name, s => {
 *     for (const [k, v] of Object.entries(span.attributes)) s.setAttribute(k, v);
 *     s.end();
 *   }),
 * });
 * ```
 */
export function createTelemetryModule(config: TelemetryConfig) {
	const serviceName = config.serviceName ?? "theauth";
	const includeArguments = config.includeArguments ?? false;

	function emit(span: TelemetrySpan): void {
		config.onSpan?.(span);
	}

	/**
	 * Convert an audit log entry into an OTel span and emit it.
	 */
	function emitAuthorizeSpan(entry: AuditEntry): void {
		const startTime = new Date(entry.timestamp.getTime() - entry.durationMs);
		const endTime = entry.timestamp;

		const attributes: Record<string, string | number | boolean> = {
			"service.name": serviceName,
			"theauth.agent.id": entry.agentId,
			"theauth.action": entry.action,
			"theauth.resource": entry.resource,
			"theauth.result": entry.result,
			"theauth.duration_ms": entry.durationMs,
		};

		if (entry.tokensCost !== undefined) {
			attributes["theauth.tokens_cost"] = entry.tokensCost;
		}

		if (entry.userId) {
			attributes["theauth.user.id"] = entry.userId;
		}

		if (entry.reason) {
			attributes["theauth.reason"] = entry.reason;
		}

		if (includeArguments && Object.keys(entry.parameters).length > 0) {
			attributes["theauth.arguments"] = JSON.stringify(entry.parameters);
		}

		emit({
			traceId: generateId() + generateId(),
			spanId: generateId(),
			name: "theauth.authorize",
			kind: "internal",
			startTime: startTime.toISOString(),
			endTime: endTime.toISOString(),
			attributes,
			status: entry.result === "allowed" ? "ok" : "error",
		});
	}

	/**
	 * Emit a span for a delegation chain create or revoke event.
	 */
	function emitDelegationSpan(chain: DelegationChain, action: "create" | "revoke"): void {
		const now = new Date();

		const attributes: Record<string, string | number | boolean> = {
			"service.name": serviceName,
			"theauth.delegation.id": chain.id,
			"theauth.delegation.from_agent": chain.fromAgent,
			"theauth.delegation.to_agent": chain.toAgent,
			"theauth.delegation.depth": chain.depth,
			"theauth.delegation.action": action,
			"theauth.delegation.expires_at": chain.expiresAt.toISOString(),
		};

		emit({
			traceId: generateId() + generateId(),
			spanId: generateId(),
			name: `theauth.delegation.${action}`,
			kind: "internal",
			startTime: now.toISOString(),
			endTime: now.toISOString(),
			attributes,
			status: "ok",
		});
	}

	/**
	 * Emit a span for an agent lifecycle event (create, revoke, rotate).
	 */
	function emitAgentSpan(agent: AgentIdentity, action: "create" | "revoke" | "rotate"): void {
		const now = new Date();

		const attributes: Record<string, string | number | boolean> = {
			"service.name": serviceName,
			"theauth.agent.id": agent.id,
			"theauth.agent.name": agent.name,
			"theauth.agent.type": agent.type,
			"theauth.action": action,
		};

		if (agent.ownerId) {
			attributes["theauth.user.id"] = agent.ownerId;
		}

		emit({
			traceId: generateId() + generateId(),
			spanId: generateId(),
			name: `theauth.agent.${action}`,
			kind: "internal",
			startTime: now.toISOString(),
			endTime: now.toISOString(),
			attributes,
			status: "ok",
		});
	}

	return { emitAuthorizeSpan, emitDelegationSpan, emitAgentSpan };
}

export type TelemetryModule = ReturnType<typeof createTelemetryModule>;
