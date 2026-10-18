/**
 * Small reference guard vendor. It shows what a vendor must do: verify the
 * request signature and freshness, decide, answer with a strict verdict, and sign
 * the response over the request id.
 * With `flaw` set it breaks one rule on purpose, so the conformance checks
 * can be tested against a bad guard.
 */
import type { Server } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
	CANARY_DENY_RESOURCE,
	GUARD_PROTOCOL_VERSION,
	RESPONSE_SIGNATURE_HEADER,
	RESPONSE_TIMESTAMP_HEADER,
	SIGNATURE_HEADER,
	sign,
	signatureMatches,
	signResponse,
	TIMESTAMP_HEADER,
} from "./guard-wire.js";

export type GuardFlaw =
	| "accepts-unsigned"
	| "accepts-stale"
	| "bad-verdict"
	| "allows-malformed"
	| "slow"
	| "redirects"
	| "unsigned-response"
	| "wrong-response-secret"
	| "wrong-response-request-id"
	| "stale-response";

export interface GuardReferenceOptions {
	secret: string;
	toleranceSec?: number;
	flaw?: GuardFlaw;
	/** Delay for the "slow" flaw, in ms. */
	delayMs?: number;
}

type Res = import("node:http").ServerResponse;

function reply(res: Res, status: number, body: unknown): void {
	res.writeHead(status, { "content-type": "application/json" });
	res.end(JSON.stringify(body));
}

/** Answer 200 with a signed verdict. The response flaws break exactly one property. */
function replySigned(
	res: Res,
	opts: GuardReferenceOptions,
	requestId: string,
	verdict: unknown,
): void {
	const text = JSON.stringify(verdict);
	const headers: Record<string, string> = { "content-type": "application/json" };
	if (opts.flaw !== "unsigned-response") {
		const stale = opts.flaw === "stale-response";
		const ts = Math.floor(Date.now() / 1000) - (stale ? 3600 : 0);
		const secret = opts.flaw === "wrong-response-secret" ? `${opts.secret}-wrong` : opts.secret;
		const id = opts.flaw === "wrong-response-request-id" ? `${requestId}-other` : requestId;
		headers[RESPONSE_TIMESTAMP_HEADER] = String(ts);
		headers[RESPONSE_SIGNATURE_HEADER] = signResponse(secret, id, ts, text);
	}
	res.writeHead(200, headers);
	res.end(text);
}

/** Start the reference guard on 127.0.0.1 with a random port. */
export async function startGuardReference(
	opts: GuardReferenceOptions,
): Promise<{ url: string; close(): Promise<void> }> {
	const tolerance = opts.toleranceSec ?? 300;
	const server: Server = createServer((req, res) => {
		let raw = "";
		req.on("data", (chunk) => {
			raw += chunk;
		});
		req.on("end", () => {
			const run = (): void => {
				if (opts.flaw === "redirects") {
					res.writeHead(307, { location: "/elsewhere" });
					res.end();
					return;
				}
				const ts = String(req.headers[TIMESTAMP_HEADER] ?? "");
				const sig = String(req.headers[SIGNATURE_HEADER] ?? "");
				const fresh =
					/^\d{1,12}$/.test(ts) && Math.abs(Date.now() / 1000 - Number(ts)) <= tolerance;
				const signed = ts !== "" && signatureMatches(sign(opts.secret, Number(ts), raw), sig);
				const skipSig = opts.flaw === "accepts-unsigned";
				const skipFresh = opts.flaw === "accepts-stale";
				if (!skipSig && !(signed && (fresh || skipFresh))) {
					reply(res, 401, { error: "invalid signature or timestamp" });
					return;
				}
				let parsed:
					| { version?: string; requestId?: string; input?: { resource?: string } }
					| undefined;
				try {
					parsed = JSON.parse(raw);
				} catch {
					parsed = undefined;
				}
				const requestId = parsed?.requestId ?? "";
				if (!parsed?.input?.resource || parsed.version !== GUARD_PROTOCOL_VERSION) {
					if (opts.flaw === "allows-malformed") {
						replySigned(res, opts, requestId, { decision: "allow" });
					} else {
						reply(res, 400, { error: "malformed request" });
					}
					return;
				}
				if (opts.flaw === "bad-verdict") {
					replySigned(res, opts, requestId, { allow: true });
					return;
				}
				if (parsed.input.resource === CANARY_DENY_RESOURCE) {
					replySigned(res, opts, requestId, {
						decision: "deny",
						reason: "canary deny",
						code: "canary",
					});
				} else {
					replySigned(res, opts, requestId, { decision: "allow" });
				}
			};
			if (opts.flaw === "slow") setTimeout(run, opts.delayMs ?? 2500);
			else run();
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	return {
		url: `http://127.0.0.1:${port}/guard`,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
}
