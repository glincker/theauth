import { compareStrings } from "../internal-compare.js";
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
			.sort(compareStrings)
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
	return JSON.stringify([p.resource, p.actions, extrasKey(p)]);
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

/** Merge single-action permissions that share resource and extras into one permission each, at the position of the first occurrence. */
export function compactPermissions(atoms: Permission[]): Permission[] {
	const out: Permission[] = [];
	const at = new Map<string, number>();
	for (const a of atoms) {
		const key = JSON.stringify([a.resource, extrasKey(a)]);
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
 * True when `outer` allows every (action, resource) that `inner` allows. Built on the engine's matchResource and matchAction, so a wildcard in `inner` is only covered by an equal or broader wildcard in `outer`.
 */
export function covers(outer: Permission, inner: Permission): boolean {
	return (
		matchResource(outer.resource, inner.resource) &&
		inner.actions.every((a) => matchAction(outer.actions, a))
	);
}

/** Finite number at or above `min`, whole, else the fallback. NaN, Infinity and non-numbers use the fallback. */
export function wholeOr(value: unknown, fallback: number, min = 0): number {
	return typeof value === "number" && Number.isFinite(value)
		? Math.max(min, Math.floor(value))
		: fallback;
}

export interface GrantMatch {
	permission: Permission;
	index: number;
}

/** Most distinct (action, resource) answers remembered by a matcher. */
const MATCH_MEMO_MAX = 10_000;

function firstSegment(resource: string): string {
	const i = resource.indexOf(":");
	return i === -1 ? resource : resource.slice(0, i);
}

/**
 * First-match lookup over a fixed permission list, equal to `findMatchingPermission` but without a scan of every permission per row. A pattern whose first segment is not `*` can only match resources with that same first segment, so permissions are bucketed by it; patterns that start with `*` (or are not strings) go in a shared list. Each candidate is still decided by the engine's own `matchResource` and `matchAction`, and the lowest index wins, so results are identical to the linear scan. Answers are memoized per pair.
 */
export function createGrantMatcher(
	permissions: readonly Permission[],
): (action: string, resource: string) => GrantMatch | null {
	const buckets = new Map<string, number[]>();
	const open: number[] = [];
	permissions.forEach((p, index) => {
		const pattern: unknown = p.resource;
		if (typeof pattern !== "string" || pattern === "*" || pattern.startsWith("*:")) {
			open.push(index);
			return;
		}
		const seg = firstSegment(pattern);
		if (seg === "*") {
			open.push(index);
			return;
		}
		const list = buckets.get(seg);
		if (list) list.push(index);
		else buckets.set(seg, [index]);
	});

	const memo = new Map<string, GrantMatch | null>();

	function firstIn(
		list: readonly number[] | undefined,
		action: string,
		resource: string,
		below: number,
	) {
		if (!list) return -1;
		for (const i of list) {
			if (i >= below) return -1;
			const p = permissions[i] as Permission;
			if (matchResource(p.resource, resource) && matchAction(p.actions, action)) return i;
		}
		return -1;
	}

	return (action, resource) => {
		const memoKey = JSON.stringify([action, resource]);
		const cached = memo.get(memoKey);
		if (cached !== undefined) return cached;
		const fromBucket = firstIn(
			buckets.get(firstSegment(resource)),
			action,
			resource,
			permissions.length,
		);
		const fromOpen = firstIn(
			open,
			action,
			resource,
			fromBucket === -1 ? permissions.length : fromBucket,
		);
		const index = fromOpen === -1 ? fromBucket : fromOpen;
		const permission = index === -1 ? undefined : permissions[index];
		const result = permission ? { permission, index } : null;
		if (memo.size >= MATCH_MEMO_MAX) memo.clear();
		memo.set(memoKey, result);
		return result;
	};
}
