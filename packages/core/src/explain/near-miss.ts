import type { DelegationLink } from "../hooks/lifecycle.js";
import { matchAction, matchResource } from "../policy/abac.js";
import type { ResourceMatching } from "../policy/resource-match.js";
import type { Permission } from "../types.js";
import type { NearMiss } from "./types.js";

export const MAX_NEAR_MISSES = 3;

export interface GrantCandidate {
	source: "own" | "delegation";
	permission: Permission;
	link?: DelegationLink;
}

/** Fraction of leading ":" segments the pattern shares with the resource. A wildcard segment covers the rest. */
function segmentOverlap(pattern: string, resource: string, matching: ResourceMatching): number {
	if (matchResource(pattern, resource, matching)) return 1;
	const p = pattern.split(":");
	const r = resource.split(":");
	let shared = 0;
	for (let i = 0; i < p.length && i < r.length; i++) {
		if (p[i] !== r[i]) break;
		shared++;
	}
	return shared / Math.max(p.length, r.length);
}

/** The narrowest wildcard that would cover the resource and keeps the grant's shared prefix. */
function wildcardFor(pattern: string, resource: string): string {
	const p = pattern.split(":");
	const r = resource.split(":");
	const prefix: string[] = [];
	for (let i = 0; i < p.length && i < r.length - 1; i++) {
		if (p[i] !== r[i]) break;
		prefix.push(p[i] as string);
	}
	return prefix.length === 0 ? "*" : `${prefix.join(":")}:*`;
}

function hintFor(
	permission: Permission,
	resource: string,
	action: string,
	mismatch: NearMiss["mismatch"],
): string {
	const parts: string[] = [];
	if (mismatch.includes("resource")) {
		const wild = wildcardFor(permission.resource, resource);
		parts.push(`resource "${permission.resource}" does not cover "${resource}"; "${wild}" would`);
	}
	if (mismatch.includes("action")) {
		const held = permission.actions.length > 0 ? permission.actions.join(", ") : "none";
		parts.push(`action "${action}" is not granted (grant holds: ${held})`);
	}
	return parts.join("; ");
}

/** Top grants that almost allowed the call. Pure: no database, no clock. */
export function findNearMisses(
	grants: GrantCandidate[],
	action: string,
	resource: string,
	matching: ResourceMatching = "colon",
): NearMiss[] {
	const found: NearMiss[] = [];
	for (const { source, permission, link } of grants) {
		const resourceOk = matchResource(permission.resource, resource, matching);
		const actionOk = matchAction(permission.actions, action);
		if (resourceOk && actionOk) continue;
		const overlap = segmentOverlap(permission.resource, resource, matching);
		if (overlap === 0 && !actionOk) continue;
		const mismatch: NearMiss["mismatch"] = [];
		if (!resourceOk) mismatch.push("resource");
		if (!actionOk) mismatch.push("action");
		const score = Math.round((0.6 * overlap + (actionOk ? 0.4 : 0)) * 100) / 100;
		found.push({
			source,
			...(link ? { delegationId: link.delegationId } : {}),
			grant: { resource: permission.resource, actions: [...permission.actions] },
			mismatch,
			hint: hintFor(permission, resource, action, mismatch),
			score,
		});
	}
	return found.sort((a, b) => b.score - a.score).slice(0, MAX_NEAR_MISSES);
}
