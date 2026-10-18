import type { ExplainResult } from "../explain/types.js";

/** One line reason plus near miss hints, for assertion messages. */
export function formatExplain(r: Pick<ExplainResult, "reason" | "nearMisses">): string {
	const parts = [`reason: ${r.reason}`];
	for (const n of r.nearMisses ?? []) {
		const via =
			n.source === "delegation" ? `delegation ${n.delegationId ?? ""}`.trim() : "own grant";
		parts.push(`near miss (${via}, score ${n.score}): ${n.hint}`);
	}
	return parts.join("\n  ");
}
