import type { CheckResult, Report } from "./types.js";

const MARK: Record<CheckResult["status"], string> = {
	pass: "PASS",
	fail: "FAIL",
	skip: "SKIP",
};

export function formatReport(report: Report, verbose = false): string {
	const lines: string[] = [];
	lines.push(`theauth-conformance ${report.version}`);
	lines.push(`Target: ${report.target}`);
	lines.push("");
	for (const result of report.results) {
		lines.push(`[${MARK[result.status]}] ${result.id} (${result.severity}, ${result.spec})`);
		lines.push(`       ${result.title}`);
		lines.push(`       ${result.summary}`);
		if (verbose && result.evidence) {
			lines.push(`       evidence: ${JSON.stringify(result.evidence)}`);
		}
	}
	const { pass, fail, skip, mustFailed } = report.summary;
	lines.push("");
	lines.push(`${pass} passed, ${fail} failed (${mustFailed} must), ${skip} skipped`);
	return `${lines.join("\n")}\n`;
}
