import { matchResource } from "../policy/abac.js";
import type { Permission } from "../types.js";
import { atomKey, compactPermissions, covers, extrasKey } from "./permissions.js";
import type { ShrinkOptions, ShrinkRewrite, ShrinkSuggestion, UsageAnalysis } from "./types.js";

const DEFAULT_GENERALIZE_MIN = 3;

function parentOf(resource: string): string | null {
	if (resource.includes("*")) return null;
	const i = resource.lastIndexOf(":");
	return i > 0 ? resource.slice(0, i) : null;
}

interface Group {
	parent: string;
	action: string;
	extras: Permission;
	indexes: number[];
}

/**
 * Turn a usage analysis into a smaller permission set. Pure and deterministic:
 * the same analysis and options always give the same output, ordered as the
 * granted list was.
 *
 * A permission is kept when it has at least `minObservations` allowed calls, or
 * when its only traffic was denied for another cause (an attempt, so removing it
 * would hide the problem). Everything else is removed.
 *
 * With `generalize`, observed sibling resources under one parent are merged into
 * `parent:*`, but only when each merged resource was actually used, an existing
 * grant already covers the wildcard (the result is never broader than today),
 * and the wildcard matches no resource that was denied for lack of a grant. The
 * wildcard still admits unobserved siblings inside that existing grant, which is
 * why it is off by default and every merge is listed in `rewrites`.
 */
export function suggestShrink(analysis: UsageAnalysis, opts: ShrinkOptions = {}): ShrinkSuggestion {
	const min = Math.max(1, Math.floor(opts.minObservations ?? 1));
	const usedCount = new Map<string, number>();
	for (const u of analysis.used) usedCount.set(atomKey(u.permission), u.count);
	const attempted = new Set(analysis.attemptedOnly.map(atomKey));

	let kept: Permission[] = [];
	const removed: Permission[] = [];
	const observed = new Set<string>();
	for (const atom of analysis.granted) {
		const key = atomKey(atom);
		const n = usedCount.get(key) ?? 0;
		if (n >= min) {
			kept.push(atom);
			observed.add(key);
		} else if (attempted.has(key)) {
			kept.push(atom);
		} else {
			removed.push(atom);
		}
	}

	const rewrites: ShrinkRewrite[] = [];
	if (opts.generalize) {
		const groupMin = Math.max(2, Math.floor(opts.generalizeMin ?? DEFAULT_GENERALIZE_MIN));
		const groups = new Map<string, Group>();
		kept.forEach((atom, index) => {
			if (!observed.has(atomKey(atom))) return;
			const parent = parentOf(atom.resource);
			const action = atom.actions[0];
			if (parent === null || action === undefined) return;
			const key = `${parent}\u0000${action}\u0000${extrasKey(atom)}`;
			const g = groups.get(key);
			if (g) g.indexes.push(index);
			else groups.set(key, { parent, action, extras: atom, indexes: [index] });
		});

		const drop = new Set<number>();
		const replaceAt = new Map<number, Permission>();
		for (const g of groups.values()) {
			if (g.indexes.length < groupMin) continue;
			const to: Permission = { resource: `${g.parent}:*`, actions: [g.action] };
			if (g.extras.constraints) to.constraints = g.extras.constraints;
			if (g.extras.relation) to.relation = g.extras.relation;
			if (!analysis.granted.some((granted) => covers(granted, to))) continue;
			const widensDenied = analysis.deniedNoGrant.some(
				(d) => d.action === g.action && matchResource(to.resource, d.resource),
			);
			if (widensDenied) continue;
			const [first, ...rest] = g.indexes;
			if (first === undefined) continue;
			replaceAt.set(first, to);
			for (const i of rest) drop.add(i);
			rewrites.push({
				from: g.indexes.flatMap((i) => (kept[i] ? [kept[i]] : [])),
				to,
			});
		}
		kept = kept.flatMap((atom, i) => {
			if (drop.has(i)) return [];
			const replacement = replaceAt.get(i);
			return [replacement ?? atom];
		});
	}

	return {
		keep: compactPermissions(kept),
		remove: compactPermissions(removed),
		rewrites,
	};
}
