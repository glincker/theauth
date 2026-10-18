/** Guard protocol wire helpers. Self-contained: the conformance package does not depend on core. */
import { createHmac, timingSafeEqual } from "node:crypto";

export const GUARD_PROTOCOL_VERSION = "2026-10";
export const TIMESTAMP_HEADER = "x-theauth-timestamp";
export const SIGNATURE_HEADER = "x-theauth-signature";
export const RESPONSE_TIMESTAMP_HEADER = "x-theauth-response-timestamp";
export const RESPONSE_SIGNATURE_HEADER = "x-theauth-response-signature";
export const VERSION_HEADER = "x-theauth-guard-version";
/** Latency budget, matches the default hook timeout in core. */
export const GUARD_LATENCY_BUDGET_MS = 2000;
export const CANARY_ALLOW_RESOURCE = "conformance:canary:allow";
export const CANARY_DENY_RESOURCE = "conformance:canary:deny";

export function sign(secret: string, timestamp: number, body: string): string {
	return `v1=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

/** Response signature, bound to the request id: HMAC over `<requestId>.<timestamp>.<body>`. */
export function signResponse(
	secret: string,
	requestId: string,
	timestamp: number,
	body: string,
): string {
	return `v1=${createHmac("sha256", secret).update(`${requestId}.${timestamp}.${body}`).digest("hex")}`;
}

export function signatureMatches(expected: string, given: string): boolean {
	const a = Buffer.from(expected);
	const b = Buffer.from(given);
	return a.length === b.length && timingSafeEqual(a, b);
}

export interface CanaryOptions {
	resource: string;
	dryRun?: boolean;
}

/** A well-formed request envelope for a synthetic agent. */
export function canaryEnvelope(opts: CanaryOptions): Record<string, unknown> {
	return {
		version: GUARD_PROTOCOL_VERSION,
		requestId: `conformance-${Math.random().toString(36).slice(2, 12)}`,
		issuedAt: new Date().toISOString(),
		input: {
			agentId: "agent_conformance",
			action: "read",
			resource: opts.resource,
			arguments: { canary: true },
			agent: {
				id: "agent_conformance",
				ownerId: "user_conformance",
				type: "autonomous",
				name: "conformance",
			},
			delegation: { path: ["agent_conformance"], links: [], inbound: [] },
			source: "authorize",
			dryRun: opts.dryRun ?? false,
		},
	};
}

export type VerdictCheck =
	| { ok: true; decision: "allow" | "deny" | "escalate" }
	| { ok: false; why: string };

const ALLOWED_KEYS: Record<string, string[]> = {
	allow: ["decision", "reason", "guard", "ruleId", "metadata"],
	escalate: ["decision", "reason", "guard", "ruleId", "metadata"],
	deny: ["decision", "reason", "code", "guard", "ruleId", "metadata"],
};

/** Strict verdict validation, the same rules `httpGuard` applies. */
export function validateVerdict(value: unknown): VerdictCheck {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return { ok: false, why: "verdict is not a JSON object" };
	}
	const v = value as Record<string, unknown>;
	const decision = v.decision;
	if (decision !== "allow" && decision !== "deny" && decision !== "escalate") {
		return { ok: false, why: "decision must be allow, deny or escalate" };
	}
	const extra = Object.keys(v).filter((k) => !ALLOWED_KEYS[decision]?.includes(k));
	if (extra.length > 0) return { ok: false, why: `unknown field: ${extra[0]}` };
	for (const key of ["reason", "code", "guard", "ruleId"]) {
		if (v[key] !== undefined && typeof v[key] !== "string") {
			return { ok: false, why: `${key} must be a string` };
		}
	}
	if (decision === "deny" && (typeof v.reason !== "string" || v.reason.length === 0)) {
		return { ok: false, why: "deny needs a non-empty reason" };
	}
	return { ok: true, decision };
}
