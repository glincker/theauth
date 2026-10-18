import type { ExplainOptions, ExplainResult } from "../explain/types.js";
import type { DecisionCode } from "../permission/codes.js";
import type { TheAuth } from "../theauth.js";
import type { Permission } from "../types.js";
import { formatExplain } from "./format.js";

export interface PolicySuiteAgent {
	permissions: Permission[];
	/** Grant these permissions to the agent through a delegation from another agent of the suite. */
	delegatedFrom?: { agent: string; permissions: Permission[] };
}

export interface PolicyCase {
	name: string;
	agent: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	expect: "allow" | "deny" | "escalate";
	/** When set, the decision code must match too. */
	code?: DecisionCode;
}

export interface PolicySuite {
	agents: Record<string, PolicySuiteAgent>;
	cases: PolicyCase[];
}

export interface PolicyFailure {
	name: string;
	expected: string;
	got: ExplainResult;
}

export interface PolicySuiteReport {
	passed: number;
	failed: PolicyFailure[];
}

export interface RunPolicySuiteOptions {
	/** Create the suite's agents and delegations first. Default true. Pass false to treat `case.agent` as an existing agent id. */
	seed?: boolean;
	/** Passed to every explain() call. */
	explain?: Pick<ExplainOptions, "at" | "context" | "runHooks">;
}

export function definePolicySuite(suite: PolicySuite): PolicySuite {
	return suite;
}

const SEED_OWNER = "policy-suite-owner";
const DAY_MS = 24 * 60 * 60 * 1000;

async function seedSuite(auth: TheAuth, suite: PolicySuite): Promise<Map<string, string>> {
	const ids = new Map<string, string>();
	try {
		await auth.user.create({ id: SEED_OWNER, email: "policy-suite@theauth.test" });
	} catch {
		// A previous run on the same instance already created the owner.
	}
	const names = Object.keys(suite.agents);
	for (const name of names) {
		const def = suite.agents[name];
		if (!def) continue;
		const agent = await auth.agent.create({
			ownerId: SEED_OWNER,
			name,
			type: "autonomous",
			permissions: def.delegatedFrom ? [] : def.permissions,
		});
		ids.set(name, agent.id);
	}
	for (const name of names) {
		const def = suite.agents[name];
		if (!def?.delegatedFrom) continue;
		const from = ids.get(def.delegatedFrom.agent);
		const to = ids.get(name);
		if (!from || !to) {
			throw new Error(`Agent "${name}" delegates from unknown agent "${def.delegatedFrom.agent}"`);
		}
		await auth.delegate({
			fromAgent: from,
			toAgent: to,
			permissions: def.delegatedFrom.permissions,
			expiresAt: new Date(Date.now() + DAY_MS),
		});
	}
	return ids;
}

/** Evaluates every case with explain(): read-only, no audit rows. */
export async function runPolicySuite(
	auth: TheAuth,
	suite: PolicySuite,
	options: RunPolicySuiteOptions = {},
): Promise<PolicySuiteReport> {
	const ids = options.seed === false ? new Map<string, string>() : await seedSuite(auth, suite);
	const report: PolicySuiteReport = { passed: 0, failed: [] };
	for (const c of suite.cases) {
		const result = await auth.explain(ids.get(c.agent) ?? c.agent, c.action, c.resource, {
			...options.explain,
			arguments: c.arguments,
		});
		const label = `${c.expect}${c.code ? ` (${c.code})` : ""}`;
		if (!result.success) {
			throw new Error(`explain failed for case "${c.name}": ${result.error.message}`);
		}
		const got = result.data;
		if (got.decision === c.expect && (c.code === undefined || got.code === c.code)) {
			report.passed++;
		} else {
			report.failed.push({ name: c.name, expected: label, got });
		}
	}
	return report;
}

/** Plain text failure report with the explain reason and near misses per failed case. */
export function formatPolicyReport(report: PolicySuiteReport): string {
	const lines = [`${report.passed} passed, ${report.failed.length} failed`];
	for (const f of report.failed) {
		lines.push(`FAIL ${f.name}: expected ${f.expected}, got ${f.got.decision} (${f.got.code})`);
		lines.push(`  ${formatExplain(f.got)}`);
	}
	return lines.join("\n");
}
