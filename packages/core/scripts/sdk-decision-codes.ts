/**
 * Keeps the Python and Go client decision code lists in step with `DECISION_CODES` in core.
 *
 * Each client file holds a region between `BEGIN GENERATED decision-codes` and `END GENERATED decision-codes`
 * markers. `scripts/generate-openapi.ts` rewrites the regions (and fails `check` when they are stale), and
 * `tests/sdk-decision-codes.test.ts` fails when a client drifts. Edit the codes in `src/permission/codes.ts`,
 * never inside a region.
 */
import { DECISION_CODES } from "../src/permission/codes.js";

export const CODES: readonly string[] = Object.values(DECISION_CODES);

const ACRONYMS: Record<string, string> = { ip: "IP" };

/** `approval_step_up_insufficient` becomes `ApprovalStepUpInsufficient`, `ip_not_allowed` becomes `IPNotAllowed`. */
export function goName(code: string): string {
	return code
		.split("_")
		.map((p) => ACRONYMS[p] ?? p.charAt(0).toUpperCase() + p.slice(1))
		.join("");
}

export interface Region {
	file: string;
	begin: string;
	end: string;
	body: string;
}

/** Files are relative to the repo root (the directory that holds `sdks/`). */
export function regions(codes: readonly string[] = CODES): Region[] {
	const quoted = codes.map((c) => `    "${c}",`).join("\n");
	const width = Math.max(...codes.map((c) => goName(c).length)) + "Decision".length;
	const consts = codes
		.map((c) => `\t${`Decision${goName(c)}`.padEnd(width)} DecisionCode = "${c}"`)
		.join("\n");
	const py = "sdks/python/theauth/codes.py";
	return [
		{
			file: py,
			begin: "    # BEGIN GENERATED decision-codes literal",
			end: "    # END GENERATED decision-codes literal",
			body: quoted,
		},
		{
			file: py,
			begin: "    # BEGIN GENERATED decision-codes tuple",
			end: "    # END GENERATED decision-codes tuple",
			body: quoted,
		},
		{
			file: "sdks/go/decision.go",
			begin: "\t// BEGIN GENERATED decision-codes",
			end: "\t// END GENERATED decision-codes",
			body: consts,
		},
	];
}

/** Replace the text between the markers. Returns null when the markers are missing. */
export function applyRegion(source: string, region: Region): string | null {
	const start = source.indexOf(region.begin);
	const stop = source.indexOf(region.end);
	if (start < 0 || stop < start) return null;
	const head = source.slice(0, start + region.begin.length);
	return `${head}\n${region.body}\n${source.slice(stop)}`;
}
