import type { ExplainOptions, ExplainResult } from "../explain/types.js";
import type { DecisionCode } from "../permission/codes.js";
import type { TheAuth } from "../theauth.js";
import type { AuthorizeResult } from "../types.js";
import { formatExplain } from "./format.js";

export interface MatcherResult {
	pass: boolean;
	message: () => string;
}

type Verdict = AuthorizeResult | ExplainResult;

function describe(r: Verdict): string {
	const head = `allowed=${r.allowed}${r.code ? ` code=${r.code}` : ""}`;
	if ("nearMisses" in r) return `${head}\n  ${formatExplain(r)}`;
	return r.reason ? `${head} reason: ${r.reason}` : head;
}

/** Plain functions shaped for `expect.extend`. No vitest import. */
export const theauthMatchers = {
	toBeAllowed(r: Verdict): MatcherResult {
		return {
			pass: r.allowed,
			message: () =>
				r.allowed ? `expected a denial, got ${describe(r)}` : `expected allow, got ${describe(r)}`,
		};
	},
	toBeDeniedWith(r: Verdict, code: DecisionCode): MatcherResult {
		const pass = !r.allowed && r.code === code;
		return {
			pass,
			message: () =>
				pass
					? `expected the call not to be denied with "${code}"`
					: `expected denial with "${code}", got ${describe(r)}`,
		};
	},
};

export interface PolicyCall {
	agentId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	options?: Omit<ExplainOptions, "arguments">;
}

async function explainCall(auth: TheAuth, call: PolicyCall): Promise<ExplainResult> {
	const r = await auth.explain(call.agentId, call.action, call.resource, {
		...call.options,
		arguments: call.arguments,
	});
	if (!r.success) throw new Error(`explain failed: ${r.error.message}`);
	return r.data;
}

/** Throws with the explain output unless the call would be allowed. Read-only. */
export async function expectAllowed(auth: TheAuth, call: PolicyCall): Promise<ExplainResult> {
	const r = await explainCall(auth, call);
	const m = theauthMatchers.toBeAllowed(r);
	if (!m.pass) throw new Error(`${call.action} ${call.resource}: ${m.message()}`);
	return r;
}

/** Throws with the explain output unless the call would be denied (with `code` when given). Read-only. */
export async function expectDenied(
	auth: TheAuth,
	call: PolicyCall,
	code?: DecisionCode,
): Promise<ExplainResult> {
	const r = await explainCall(auth, call);
	const bad = r.allowed || (code !== undefined && r.code !== code);
	if (bad) {
		const want = code ? `denial with "${code}"` : "a denial";
		throw new Error(`${call.action} ${call.resource}: expected ${want}, got ${describe(r)}`);
	}
	return r;
}
