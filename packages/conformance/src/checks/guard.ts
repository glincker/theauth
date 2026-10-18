import type { Context } from "../context.js";
import {
	CANARY_ALLOW_RESOURCE,
	CANARY_DENY_RESOURCE,
	canaryEnvelope,
	GUARD_LATENCY_BUDGET_MS,
	GUARD_PROTOCOL_VERSION,
	RESPONSE_SIGNATURE_HEADER,
	RESPONSE_TIMESTAMP_HEADER,
	SIGNATURE_HEADER,
	sign,
	signatureMatches,
	signResponse,
	TIMESTAMP_HEADER,
	VERSION_HEADER,
	validateVerdict,
} from "../guard-wire.js";
import { excerpt } from "../http.js";
import type { Check } from "./helpers.js";
import { fail, pass, skip } from "./helpers.js";

interface SendOptions {
	body?: string;
	secret?: string | null;
	timestamp?: number;
	signature?: string;
}

const now = (): number => Math.floor(Date.now() / 1000);

async function post(ctx: Context, o: SendOptions) {
	const body = o.body ?? JSON.stringify(canaryEnvelope({ resource: CANARY_ALLOW_RESOURCE }));
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		Accept: "application/json",
		[VERSION_HEADER]: GUARD_PROTOCOL_VERSION,
	};
	const ts = o.timestamp ?? now();
	if (o.secret !== null) {
		headers[TIMESTAMP_HEADER] = String(ts);
		headers[SIGNATURE_HEADER] = o.signature ?? sign(o.secret ?? "", ts, body);
	}
	return ctx.send(ctx.opts.target, { method: "POST", headers, body });
}

function secretOf(ctx: Context): string {
	return ctx.opts.guardSecret ?? "";
}

function missingSecret() {
	return skip("No --secret given (or THEAUTH_GUARD_SECRET), cannot sign requests.");
}

/** A rejection is a 4xx. An `allow` verdict on a bad request is the failure we look for. */
function judgeRejection(res: { status: number; text: string; json: unknown }, what: string) {
	const verdict = validateVerdict(res.json);
	if (res.status >= 200 && res.status < 300) {
		if (verdict.ok && verdict.decision === "deny") {
			return pass(`${what} got a deny verdict.`, { status: res.status });
		}
		return fail(`${what} was accepted with HTTP ${res.status}. It must be refused (401 or 403).`, {
			status: res.status,
			body: excerpt(res.text),
		});
	}
	if (res.status >= 400 && res.status < 500)
		return pass(`${what} was refused with HTTP ${res.status}.`);
	return fail(`${what} got HTTP ${res.status}, expected a 4xx refusal.`, { status: res.status });
}

async function canary(ctx: Context, resource: string, expected: "allow" | "deny", dryRun = false) {
	const body = JSON.stringify(canaryEnvelope({ resource, dryRun }));
	const res = await post(ctx, { body, secret: secretOf(ctx) });
	const evidence = { status: res.status, body: excerpt(res.text) };
	if (res.status < 200 || res.status >= 300) {
		return fail(`A validly signed canary got HTTP ${res.status}, expected 200.`, evidence);
	}
	const verdict = validateVerdict(res.json);
	if (!verdict.ok) return fail(`Verdict is not valid: ${verdict.why}.`, evidence);
	if (verdict.decision !== expected) {
		return fail(`Canary ${expected} resource got "${verdict.decision}".`, evidence);
	}
	return pass(`Valid ${expected} verdict.`, { status: res.status });
}

const RESPONSE_TOLERANCE_SEC = 300;

type ResponseProblem = "missing" | "signature" | "stale";

/** Send a valid canary and judge the response signature. Returns the problem, or null when fine. */
async function inspectResponse(
	ctx: Context,
): Promise<{ problem: ResponseProblem | null; status: number; detail: string }> {
	const envelope = canaryEnvelope({ resource: CANARY_ALLOW_RESOURCE });
	const requestId = String(envelope.requestId);
	const res = await post(ctx, { body: JSON.stringify(envelope), secret: secretOf(ctx) });
	const ts = res.headers.get(RESPONSE_TIMESTAMP_HEADER);
	const sig = res.headers.get(RESPONSE_SIGNATURE_HEADER);
	if (res.status < 200 || res.status >= 300) {
		return { problem: "missing", status: res.status, detail: `canary got HTTP ${res.status}` };
	}
	if (!ts || !sig) {
		return { problem: "missing", status: res.status, detail: "response signature headers absent" };
	}
	if (!/^\d{1,12}$/.test(ts)) {
		return { problem: "signature", status: res.status, detail: "response timestamp is malformed" };
	}
	if (!signatureMatches(signResponse(secretOf(ctx), requestId, Number(ts), res.text), sig)) {
		return {
			problem: "signature",
			status: res.status,
			detail: "signature does not match secret, request id and body",
		};
	}
	if (Math.abs(now() - Number(ts)) > RESPONSE_TOLERANCE_SEC) {
		return {
			problem: "stale",
			status: res.status,
			detail: "response timestamp is outside the window",
		};
	}
	return { problem: null, status: res.status, detail: "ok" };
}

function responseCheck(
	id: string,
	title: string,
	problems: ResponseProblem[],
	passMessage: string,
	failMessage: string,
): Check {
	return {
		id,
		title,
		spec: "theauth guard protocol 2026-10, signed responses",
		severity: "must",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			const r = await inspectResponse(ctx);
			if (r.problem !== null && problems.includes(r.problem)) {
				return fail(`${failMessage} (${r.detail}).`, { status: r.status });
			}
			return r.problem === null ? pass(passMessage, { status: r.status }) : fail(`${r.detail}.`);
		},
	};
}

export const guardChecks: Check[] = [
	{
		id: "guard-rejects-unsigned",
		title: "A request without signature headers is refused",
		spec: "theauth guard protocol 2026-10, signing",
		severity: "must",
		async run(ctx) {
			return judgeRejection(await post(ctx, { secret: null }), "An unsigned request");
		},
	},
	{
		id: "guard-rejects-bad-signature",
		title: "A request signed with the wrong secret is refused",
		spec: "theauth guard protocol 2026-10, signing",
		severity: "must",
		async run(ctx) {
			return judgeRejection(
				await post(ctx, { secret: `${secretOf(ctx)}-wrong` }),
				"A request with a wrong signature",
			);
		},
	},
	{
		id: "guard-rejects-stale",
		title: "A correctly signed request older than the replay window is refused",
		spec: "theauth guard protocol 2026-10, replay window",
		severity: "must",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			return judgeRejection(
				await post(ctx, { secret: secretOf(ctx), timestamp: now() - 3600 }),
				"A stale request",
			);
		},
	},
	{
		id: "guard-canary-allow",
		title: "A signed canary allow request returns a valid allow verdict",
		spec: "theauth guard protocol 2026-10, verdict schema",
		severity: "must",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			return canary(ctx, CANARY_ALLOW_RESOURCE, "allow");
		},
	},
	{
		id: "guard-canary-deny",
		title: "A signed canary deny request returns a valid deny verdict with a reason",
		spec: "theauth guard protocol 2026-10, verdict schema",
		severity: "must",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			return canary(ctx, CANARY_DENY_RESOURCE, "deny");
		},
	},
	{
		id: "guard-malformed-input",
		title: "A signed but malformed body is never allowed",
		spec: "theauth guard protocol 2026-10, fail closed",
		severity: "must",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			const bodies = ["not json at all", JSON.stringify({ version: GUARD_PROTOCOL_VERSION })];
			for (const body of bodies) {
				const res = await post(ctx, { body, secret: secretOf(ctx) });
				const outcome = judgeRejection(res, "A malformed body");
				if (outcome.status === "fail") return outcome;
			}
			return pass("Malformed bodies were refused.");
		},
	},
	{
		id: "guard-dry-run",
		title: "A dryRun canary gets a valid verdict",
		spec: "theauth guard protocol 2026-10, dryRun",
		severity: "should",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			return canary(ctx, CANARY_ALLOW_RESOURCE, "allow", true);
		},
	},
	{
		id: "guard-no-redirect",
		title: "The endpoint answers directly and does not redirect",
		spec: "theauth guard protocol 2026-10, transport",
		severity: "must",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			const res = await post(ctx, { secret: secretOf(ctx) });
			return res.status >= 300 && res.status < 400
				? fail(`Endpoint redirected (HTTP ${res.status}). httpGuard refuses redirects.`, {
						location: res.headers.get("location"),
					})
				: pass("No redirect.");
		},
	},
	{
		id: "guard-latency",
		title: `A canary answers within ${GUARD_LATENCY_BUDGET_MS} ms`,
		spec: "theauth guard protocol 2026-10, latency budget",
		severity: "should",
		async run(ctx) {
			if (!secretOf(ctx)) return missingSecret();
			const times: number[] = [];
			for (let i = 0; i < 3; i += 1) {
				const started = Date.now();
				const res = await post(ctx, { secret: secretOf(ctx) });
				if (res.status !== 200) return fail(`Canary got HTTP ${res.status}.`);
				times.push(Date.now() - started);
			}
			const worst = Math.max(...times);
			const evidence = { timesMs: times, budgetMs: GUARD_LATENCY_BUDGET_MS };
			return worst <= GUARD_LATENCY_BUDGET_MS
				? pass(`Slowest of 3 canaries took ${worst} ms.`, evidence)
				: fail(
						`Slowest of 3 canaries took ${worst} ms, over the ${GUARD_LATENCY_BUDGET_MS} ms budget.`,
						evidence,
					);
		},
	},
	responseCheck(
		"guard-response-signed",
		"A verdict carries x-theauth-response-signature and x-theauth-response-timestamp",
		["missing"],
		"Response is signed.",
		"The response is not signed. httpGuard denies unsigned responses",
	),
	responseCheck(
		"guard-response-signature",
		"The response signature uses the shared secret and is bound to the request id",
		["signature"],
		"Signature matches secret, request id and body.",
		"The response signature is wrong. Sign <requestId>.<timestamp>.<body> with the shared secret",
	),
	responseCheck(
		"guard-response-fresh",
		"The response timestamp is within the replay window",
		["stale"],
		"Response timestamp is fresh.",
		"The response timestamp is stale. Use the current unix time",
	),
];
