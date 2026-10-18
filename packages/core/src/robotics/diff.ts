import { ddsTopicsForRules } from "./dds-topics.js";
import type { BuildRosPolicyOptions, RoboticsPermission } from "./policy-model.js";
import { buildRosPolicy } from "./policy-model.js";

export interface RosPolicyDiff {
	publish: { added: string[]; removed: string[] };
	subscribe: { added: string[]; removed: string[] };
	/** Resources that became or stopped being gated. */
	gated: { added: string[]; removed: string[] };
	empty: boolean;
}

function delta(before: string[], after: string[]): { added: string[]; removed: string[] } {
	const b = new Set(before);
	const a = new Set(after);
	return {
		added: after.filter((x) => !b.has(x)),
		removed: before.filter((x) => !a.has(x)),
	};
}

/** What changes on the DDS side, and in the gated set, when moving from one permission list to another. */
export function diffRosPolicies(
	before: readonly RoboticsPermission[],
	after: readonly RoboticsPermission[],
	options: BuildRosPolicyOptions = {},
): RosPolicyDiff {
	const a = buildRosPolicy(before, options);
	const b = buildRosPolicy(after, options);
	const ta = ddsTopicsForRules(a.rules);
	const tb = ddsTopicsForRules(b.rules);
	const gatedKey = (g: { resource: string; actions: string[] }) =>
		`${g.resource} [${[...g.actions].sort().join(",")}]`;
	const result = {
		publish: delta(ta.publish, tb.publish),
		subscribe: delta(ta.subscribe, tb.subscribe),
		gated: delta(a.gated.map(gatedKey).sort(), b.gated.map(gatedKey).sort()),
	};
	const empty = [result.publish, result.subscribe, result.gated].every(
		(d) => d.added.length === 0 && d.removed.length === 0,
	);
	return { ...result, empty };
}
