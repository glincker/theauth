import { guardChecks } from "./checks/guard.js";
import type { Check } from "./checks/index.js";
import { ALL_CHECKS } from "./checks/index.js";
import { createContext } from "./context.js";
import type { CheckOutcome, CheckResult, Options, Report, Summary } from "./types.js";
import { TOOL_NAME, VERSION } from "./version.js";

export function summarize(results: CheckResult[]): Summary {
	const summary: Summary = { pass: 0, fail: 0, skip: 0, mustFailed: 0 };
	for (const result of results) {
		summary[result.status] += 1;
		if (result.status === "fail" && result.severity === "must") summary.mustFailed += 1;
	}
	return summary;
}

async function runOne(check: Check, ctx: ReturnType<typeof createContext>): Promise<CheckResult> {
	const started = Date.now();
	let outcome: CheckOutcome;
	try {
		outcome = await check.run(ctx);
	} catch (error) {
		// A network failure or timeout is a failed check, never a silent pass.
		const message = error instanceof Error ? error.message : "unknown error";
		outcome = {
			status: "fail",
			summary: `Request failed: ${message}`,
			evidence: { error: message },
		};
	}
	return {
		id: check.id,
		title: check.title,
		spec: check.spec,
		severity: check.severity,
		...outcome,
		durationMs: Date.now() - started,
	};
}

export async function runSuite(
	options: Options,
	checks: Check[] = options.mode === "guard" ? guardChecks : ALL_CHECKS,
): Promise<Report> {
	const ctx = createContext(options);
	const results: CheckResult[] = [];
	for (const check of checks) {
		results.push(await runOne(check, ctx));
	}
	return {
		tool: TOOL_NAME,
		version: VERSION,
		target: options.target,
		generatedAt: new Date().toISOString(),
		summary: summarize(results),
		results,
	};
}
