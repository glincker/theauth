/**
 * Small reference guard vendor. It shows the three things a vendor must do:
 * verify the signature and freshness, decide, answer with a strict verdict.
 * With `flaw` set it breaks one rule on purpose, so the conformance checks
 * can be tested against a bad guard.
 */
import type { Server } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
	CANARY_DENY_RESOURCE,
	GUARD_PROTOCOL_VERSION,
	SIGNATURE_HEADER,
	sign,
	signatureMatches,
	TIMESTAMP_HEADER,
} from "./guard-wire.js";

export type GuardFlaw =
	| "accepts-unsigned"
	| "accepts-stale"
	| "bad-verdict"
	| "allows-malformed"
	| "slow"
	| "redirects";

export interface GuardReferenceOptions {
	secret: string;
	toleranceSec?: number;
	flaw?: GuardFlaw;
	/** Delay for the "slow" flaw, in ms. */
	delayMs?: number;
}

function reply(res: import("node:http").ServerResponse, status: number, body: unknown): void {
	res.writeHead(status, { "content-type": "application/json" });
	res.end(JSON.stringify(body));
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
				let parsed: { version?: string; input?: { resource?: string } } | undefined;
				try {
					parsed = JSON.parse(raw);
				} catch {
					parsed = undefined;
				}
				if (!parsed?.input?.resource || parsed.version !== GUARD_PROTOCOL_VERSION) {
					if (opts.flaw === "allows-malformed") {
						reply(res, 200, { decision: "allow" });
					} else {
						reply(res, 400, { error: "malformed request" });
					}
					return;
				}
				if (opts.flaw === "bad-verdict") {
					reply(res, 200, { allow: true });
					return;
				}
				if (parsed.input.resource === CANARY_DENY_RESOURCE) {
					reply(res, 200, { decision: "deny", reason: "canary deny", code: "canary" });
				} else {
					reply(res, 200, { decision: "allow" });
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
