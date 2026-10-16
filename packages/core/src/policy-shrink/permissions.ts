import { matchAction, matchResource } from "../policy/abac.js";
import { POLICY_ERROR_CODES } from "../policy/types.js";
import type { Permission } from "../types.js";
import type { DecisionRow, RowClass } from "./types.js";

const INTERNAL_ACTIONS = new Set([
	"agent.cascade.revoked",
	"delegation.create",
	"approval.request",
]);
const NO_GRANT_PREFIX = "No permission grants";

/** Classify an audit row for usage analysis. */
export function classifyRow(row: DecisionRow): RowClass {
	if (row.action.startsWith("audit.") || INTERNAL_ACTIONS.has(row.action)) return "internal";
	if (row.result === "allowed") return "allow";
	if (
		row.result === "denied" &&
		row.reason !== null &&
		(row.reason.startsWith(NO_GRANT_PREFIX) ||
			row.reason === POLICY_ERROR_CODES.NO_MATCHING_PERMISSION)
	) {
		return "deny_no_grant";
	}
	return "deny_other";
}

/** Stable JSON with sorted keys, for comparing constraint objects. */
function stable(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
	if (value && typeof value === "object") {
		const o = value as Record<string, unknown>;
		return `{${Object.keys(o)
			.sort()
			.map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
			.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

/** Everything about a permission except its resource and actions. */
export function extrasKey(p: Permission): string {
	return stable({ constraints: p.constraints ?? null, relation: p.relation ?? null });
}

/** Identity of a single-action permission. */
export function atomKey(p: Permission): string {
	return `${p.resource}\u0000${p.actions.join(",")}\u0000${extrasKey(p)}`;
}

function withExtras(resource: string, actions: string[], from: Permission): Permission {
	const out: Permission = { resource, actions };
	if (from.constraints) out.constraints = from.constraints;
	if (from.relation) out.relation = from.relation;
	return out;
}

/** Split a permission into one permission per action (deduplicated, input order). */
export function splitPermission(p: Permission): Permission[] {
	return [...new Set(p.actions)].map((a) => withExtras(p.resource, [a], p));
}

/**
 * Merge single-action permissions that share resource and extras into one
 * permission each, at the position of the first occurrence.
 */
export function compactPermissions(atoms: Permission[]): Permission[] {
	const out: Permission[] = [];
	const at = new Map<string, number>();
	for (const a of atoms) {
		const key = `${a.resource}\u0000${extrasKey(a)}`;
		const i = at.get(key);
		const existing = i === undefined ? undefined : out[i];
		if (existing) {
			for (const act of a.actions) if (!existing.actions.includes(act)) existing.actions.push(act);
		} else {
			at.set(key, out.length);
			out.push(withExtras(a.resource, [...a.actions], a));
		}
	}
	return out;
}

/**
 * True when `outer` allows every (action, resource) that `inner` allows.
 * Built on the engine's matchResource and matchAction, so a wildcard in
 * `inner` is only covered by an equal or broader wildcard in `outer`.
 */
export function covers(outer: Permission, inner: Permission): boolean {
	return (
		matchResource(outer.resource, inner.resource) &&
		inner.actions.every((a) => matchAction(outer.actions, a))
	);
}
