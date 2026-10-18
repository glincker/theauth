import type { Permission } from "../types.js";
import type { RosKind, RosVerb } from "./names.js";
import { parseRosResource, verbsForAction } from "./names.js";

/** A theAuth permission as the exporter reads it. `Permission` from core satisfies this. */
export interface RoboticsPermission {
	resource: Permission["resource"];
	actions: Permission["actions"];
	/** Any constraint DDS cannot express makes the permission "gated", see `buildRosPolicy`. */
	constraints?: object | undefined;
}

export interface RosRule {
	kind: RosKind;
	/** Absolute name, or `/*` for every name of the kind. */
	name: string;
	verbs: RosVerb[];
}

export interface GatedPermission {
	resource: string;
	actions: string[];
	/** Constraint names that DDS permissions cannot enforce, for example `requireApproval`. */
	constraints: string[];
}

export interface SkippedPermission {
	resource: string;
	actions: string[];
	reason: string;
}

export interface RosPolicy {
	rules: RosRule[];
	gated: GatedPermission[];
	skipped: SkippedPermission[];
}

export interface BuildRosPolicyOptions {
	/**
	 * What to do with permissions that carry constraints (approval, step up, rate, time window, ip,
	 * argument patterns). DDS permissions are static, so none of these can be enforced there.
	 * "omit" (default) leaves them out, so the enclave cannot do the thing at all and a trusted
	 * gate process must hold the grant. "include" grants them statically and relies on the runtime
	 * gate alone, which a participant holding the enclave key can bypass.
	 */
	gated?: "omit" | "include";
}

/** Constraint names that carry a real restriction. Empty arrays, false and undefined do not count. */
function activeConstraints(constraints: object | undefined): string[] {
	if (!constraints) return [];
	const names: string[] = [];
	for (const [key, value] of Object.entries(constraints)) {
		if (value === undefined || value === null || value === false) continue;
		if (Array.isArray(value) && value.length === 0) continue;
		names.push(key);
	}
	return names.sort();
}

const KIND_ORDER: Record<RosKind, number> = { topic: 0, service: 1, action: 2 };

/**
 * Turn theAuth permissions into a ROS 2 policy model. Pure and deterministic: the output is sorted,
 * so exporting twice gives identical files and a diff shows only real changes. Anything that cannot
 * be mapped faithfully is reported in `skipped` rather than guessed.
 */
export function buildRosPolicy(
	permissions: readonly RoboticsPermission[],
	options: BuildRosPolicyOptions = {},
): RosPolicy {
	const mode = options.gated ?? "omit";
	const merged = new Map<string, RosRule>();
	const gated: GatedPermission[] = [];
	const skipped: SkippedPermission[] = [];

	for (const permission of permissions) {
		const parsed = parseRosResource(permission.resource);
		if (!parsed.ok) {
			skipped.push({
				resource: permission.resource,
				actions: [...permission.actions],
				reason: parsed.reason,
			});
			continue;
		}
		const active = activeConstraints(permission.constraints);
		if (active.length > 0) {
			gated.push({
				resource: permission.resource,
				actions: [...permission.actions],
				constraints: active,
			});
			if (mode === "omit") continue;
		}
		const unknown = permission.actions.filter((action) =>
			parsed.kinds.every((kind) => verbsForAction(kind, action).length === 0),
		);
		if (unknown.length > 0) {
			skipped.push({
				resource: permission.resource,
				actions: unknown,
				reason: "no ROS 2 verb for this action (use publish, subscribe, call, reply, execute or *)",
			});
		}
		for (const kind of parsed.kinds) {
			const verbs = permission.actions.flatMap((action) => verbsForAction(kind, action));
			if (verbs.length === 0) continue;
			const name = parsed.name ?? "/*";
			const key = `${kind}\u0000${name}`;
			const existing = merged.get(key);
			const set = new Set([...(existing?.verbs ?? []), ...verbs]);
			merged.set(key, { kind, name, verbs: [...set].sort() });
		}
	}

	const rules = [...merged.values()].sort(
		(a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || a.name.localeCompare(b.name),
	);
	return { rules, gated, skipped };
}
