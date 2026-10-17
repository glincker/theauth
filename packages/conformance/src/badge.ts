import type { Report, ShieldsBadge } from "./types.js";

/**
 * Build a shields.io endpoint badge (https://shields.io/badges/endpoint-badge).
 * Green: nothing failed. Yellow: only SHOULD or MAY checks failed. Red: a MUST failed.
 * Grey: no check could run, so nothing is claimed.
 */
export function buildBadge(report: Report): ShieldsBadge {
	const { pass, fail, skip, mustFailed } = report.summary;
	const ran = pass + fail;
	if (ran === 0) {
		return { schemaVersion: 1, label: "agent-auth", message: "not tested", color: "lightgrey" };
	}
	const skipped = skip > 0 ? `, ${skip} skipped` : "";
	const color = mustFailed > 0 ? "red" : fail > 0 ? "yellow" : "brightgreen";
	return {
		schemaVersion: 1,
		label: "agent-auth",
		message: `${pass}/${ran} passed${skipped}`,
		color,
	};
}
