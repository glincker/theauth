// Pure helpers and small queries used by the policy engine, split out to keep engine.ts under 500 lines.

import { eq } from "drizzle-orm";
import { captureInputProvenance, withInputSources } from "../audit/provenance.js";
import type { Database } from "../db/database.js";
import { permissions as permissionsTable } from "../db/schema.js";
import { getDelegatedPermissions } from "../delegation/delegation.js";
import type { Permission } from "../types.js";
import type { createRbacResolver } from "./rbac.js";
import { normalizeProvenance } from "./taint.js";
import type { EvaluateInput, PolicyDecision } from "./types.js";
import { POLICY_ERROR_CODES } from "./types.js";

/** The input_provenance value for the audit row: labels, the taint verdict and the captured input sources (hashes only), or undefined. */
export async function provenanceRecord(
	db: Database,
	input: EvaluateInput,
	decision: PolicyDecision,
): Promise<Record<string, unknown> | undefined> {
	const labels = normalizeProvenance(input.context?.provenance);
	const base =
		!labels && !decision.taint
			? undefined
			: {
					labels: labels ?? {},
					...(decision.taint
						? { taint: { verdict: decision.taint.verdict, matches: decision.taint.matches } }
						: {}),
				};
	return withInputSources(base, await captureInputProvenance(db, input.context?.inputs));
}

export function buildCacheKey(input: EvaluateInput): string {
	// orgId scopes RBAC role lookup, so two requests from the same user against
	// different orgs MUST get different keys. Use an explicit sentinel when
	// orgId is omitted so { user: u, orgId: undefined } cannot collide with
	// { user: u, orgId: "" } or any other unscoped form.
	const subjectKey = input.subject.agentId ?? input.subject.userId ?? "";
	const orgKey = input.subject.orgId ?? "__noorg__";
	const ipKey = input.context?.ip ?? "";
	return `${subjectKey}|${orgKey}|${input.action}|${input.resource}|${ipKey}`;
}

export function validateInput(input: EvaluateInput): { ok: true } | { ok: false; reason: string } {
	if (!input?.subject || !input.action || !input.resource) {
		return { ok: false, reason: POLICY_ERROR_CODES.INVALID_INPUT };
	}
	if (!input.subject.agentId && !input.subject.userId) {
		return { ok: false, reason: POLICY_ERROR_CODES.INVALID_INPUT };
	}
	return { ok: true };
}

export function clampSampleRate(rate: number | undefined): number {
	if (typeof rate !== "number" || Number.isNaN(rate)) return 1;
	if (rate < 0) return 0;
	if (rate > 1) return 1;
	return rate;
}

export function finalize(decision: PolicyDecision, start: number): PolicyDecision {
	return {
		...decision,
		durationMs: Math.round(performance.now() - start),
	};
}

export async function resolveEffectivePermissions(
	db: Database,
	rbac: ReturnType<typeof createRbacResolver>,
	input: EvaluateInput,
): Promise<Permission[]> {
	const direct = input.subject.agentId
		? await fetchDirectPermissions(db, input.subject.agentId)
		: [];
	const delegated = input.subject.agentId
		? await getDelegatedPermissions(db, input.subject.agentId)
		: [];
	const roles = input.subject.userId
		? await rbac.resolveRolePermissions({
				userId: input.subject.userId,
				orgId: input.subject.orgId,
			})
		: [];
	return [...direct, ...delegated, ...roles];
}

export async function fetchDirectPermissions(db: Database, agentId: string): Promise<Permission[]> {
	const rows = await db
		.select()
		.from(permissionsTable)
		.where(eq(permissionsTable.agentId, agentId));
	return rows.map((r) => ({
		resource: r.resource,
		actions: r.actions,
		constraints: r.constraints ?? undefined,
		relation: r.relation ?? undefined,
	}));
}

export function noop(): void {}
