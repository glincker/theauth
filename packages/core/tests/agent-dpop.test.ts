/**
 * Sender constrained agent tokens (RFC 7800, DPoP RFC 9449): binding at issue time, proof checks on the
 * REST authorize route and requireAgent, replay cache and nonces, fail closed behavior of the library
 * call, rotate and introspection. Certificate bound tokens are in agent-confirmation-methods.test.ts.
 */

import { eq } from "drizzle-orm";
import { beforeAll, describe, expect, it } from "vitest";
import { createDPoPClient } from "../../client/src/dpop.js";
import { sha256Raw, toBase64Url } from "../src/crypto/web-crypto.js";
import { agents, auditLogs } from "../src/db/schema.js";
import { createTheAuthHandler, requireAgent } from "../src/http/index.js";
import type { TheAuth } from "../src/theauth.js";
import type { Keys } from "./agent-dpop-helpers.js";
import {
	AUTHORIZE_URL,
	boundAgent,
	CALL,
	codeOf,
	makeAuth,
	newKeys,
	PERMS,
	proof,
} from "./agent-dpop-helpers.js";
import { BASE, sessionToken } from "./http/helpers.js";

function post(
	handler: ReturnType<typeof createTheAuthHandler>,
	scheme: "Bearer" | "DPoP",
	token: string,
	dpop?: string,
): Promise<Response> {
	return handler(
		new Request(AUTHORIZE_URL, {
			method: "POST",
			headers: {
				Authorization: `${scheme} ${token}`,
				"Content-Type": "application/json",
				...(dpop ? { DPoP: dpop } : {}),
			},
			body: JSON.stringify(CALL),
		}),
	);
}

describe("DPoP bound agent tokens on POST /authorize/token", () => {
	let auth: TheAuth;
	let handler: ReturnType<typeof createTheAuthHandler>;
	let keys: Keys;

	beforeAll(async () => {
		auth = await makeAuth({ dpop: {} });
		handler = createTheAuthHandler(auth, { rateLimit: false });
		keys = await newKeys();
	});

	it("allows a bound token with the DPoP scheme and a valid proof", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const res = await post(handler, "DPoP", agent.token, await proof(keys, agent.token));
		expect(res.status).toBe(200);
		expect(await codeOf(res)).toBe("allowed");
	});

	it("refuses a bound token sent as a plain bearer token, with a DPoP challenge", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const res = await post(handler, "Bearer", agent.token);
		expect(res.status).toBe(401);
		expect(await codeOf(res)).toBe("confirmation_required");
		const challenge = res.headers.get("www-authenticate") ?? "";
		expect(challenge.startsWith("DPoP ")).toBe(true);
		expect(challenge).toContain('algs="ES256');
	});

	it("refuses a proof signed by a different key", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const thief = await newKeys();
		const res = await post(handler, "DPoP", agent.token, await proof(thief, agent.token));
		expect(res.status).toBe(401);
		expect(await codeOf(res)).toBe("confirmation_failed");
	});

	it("refuses a replayed proof", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const once = await proof(keys, agent.token);
		expect((await post(handler, "DPoP", agent.token, once)).status).toBe(200);
		const again = await post(handler, "DPoP", agent.token, once);
		expect(again.status).toBe(401);
		const body = (await again.json()) as { error: string; error_description: string };
		expect(body.error).toBe("invalid_dpop_proof");
		expect(body.error_description).toContain("already been used");
	});

	it("refuses a proof for another method, URL or token", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const other = await boundAgent(auth, { jkt: keys.jkt });
		for (const init of [
			{ htm: "GET" },
			{ htu: `${BASE}/agents` },
			{ ath: toBase64Url(await sha256Raw(other.token)) },
			{ iat: Math.floor(Date.now() / 1000) - 3600 },
		]) {
			const res = await post(handler, "DPoP", agent.token, await proof(keys, agent.token, init));
			expect(res.status).toBe(401);
			expect(((await res.json()) as { error: string }).error).toBe("invalid_dpop_proof");
		}
	});

	it("refuses the DPoP scheme without a proof header", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const res = await post(handler, "DPoP", agent.token);
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toContain('error="invalid_dpop_proof"');
	});

	it("does not bother an unbound token with the DPoP machinery", async () => {
		const plain = await boundAgent(auth, undefined);
		expect((await post(handler, "Bearer", plain.token)).status).toBe(200);
		// A stray proof header on a bearer request is ignored by an unbound token.
		const withProof = await post(handler, "Bearer", plain.token, await proof(keys, plain.token));
		expect(withProof.status).toBe(200);
	});

	it("keeps the audit trail honest about a refused bound token", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		await post(handler, "Bearer", agent.token);
		const rows = await auth.db.select().from(auditLogs).where(eq(auditLogs.agentId, agent.id));
		expect(rows.some((r) => r.decisionCode === "confirmation_required")).toBe(true);
	});

	it("fails closed for a library call that skips the HTTP layer", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const bare = await auth.authorizeByToken(agent.token, CALL);
		expect(bare).toMatchObject({ allowed: false, code: "confirmation_required" });
		const wrong = await auth.authorizeByToken(agent.token, CALL, {
			confirmation: { jkt: "x".repeat(43) },
		});
		expect(wrong).toMatchObject({ allowed: false, code: "confirmation_failed" });
		const right = await auth.authorizeByToken(agent.token, CALL, {
			confirmation: { jkt: keys.jkt },
		});
		expect(right.allowed).toBe(true);
	});

	it("fails closed when the stored binding cannot be read", async () => {
		const agent = await boundAgent(auth, undefined);
		await auth.db
			.update(agents)
			.set({ cnf: { broken: 1 } as never })
			.where(eq(agents.id, agent.id));
		const res = await auth.authorizeByToken(agent.token, CALL, { confirmation: { jkt: keys.jkt } });
		expect(res).toMatchObject({ allowed: false, code: "confirmation_failed" });
	});

	it("works through requireAgent too", async () => {
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const req = async (scheme: "Bearer" | "DPoP", dpop?: string) =>
			requireAgent(
				auth,
				new Request(AUTHORIZE_URL, {
					method: "POST",
					headers: { Authorization: `${scheme} ${agent.token}`, ...(dpop ? { DPoP: dpop } : {}) },
				}),
				CALL,
			);
		const denied = await req("Bearer");
		expect(denied.ok).toBe(false);
		if (!denied.ok) {
			expect(denied.status).toBe(401);
			expect(denied.code).toBe("confirmation_required");
			expect(denied.response.headers.get("www-authenticate")).toContain("DPoP");
		}
		const allowed = await req("DPoP", await proof(keys, agent.token));
		expect(allowed.ok).toBe(true);
	});
});

describe("DPoP nonce (RFC 9449 section 9)", () => {
	it("asks for a nonce, then accepts the retry that carries it", async () => {
		const auth = await makeAuth({ dpop: { requireNonce: true } });
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const keys = await newKeys();
		const agent = await boundAgent(auth, { jkt: keys.jkt });

		const first = await post(handler, "DPoP", agent.token, await proof(keys, agent.token));
		expect(first.status).toBe(401);
		expect(first.headers.get("www-authenticate")).toContain('error="use_dpop_nonce"');
		const nonce = first.headers.get("dpop-nonce") ?? "";
		expect(nonce.length).toBeGreaterThan(10);

		const retry = await post(
			handler,
			"DPoP",
			agent.token,
			await proof(keys, agent.token, { nonce }),
		);
		expect(retry.status).toBe(200);
		const guess = await post(
			handler,
			"DPoP",
			agent.token,
			await proof(keys, agent.token, { nonce: "made-up-nonce" }),
		);
		expect(guess.status).toBe(401);
	});
});

describe("binding at issue time, rotate and the REST routes", () => {
	let auth: TheAuth;
	let handler: ReturnType<typeof createTheAuthHandler>;
	let alice: string;
	let bob: string;

	beforeAll(async () => {
		auth = await makeAuth({ dpop: {} });
		handler = createTheAuthHandler(auth, { rateLimit: false });
		alice = await sessionToken(auth, "alice");
		bob = await sessionToken(auth, "bob");
	});

	const api = (path: string, token: string, body?: unknown, method = "POST") =>
		handler(
			new Request(`${BASE}${path}`, {
				method,
				headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
				body: body === undefined ? undefined : JSON.stringify(body),
			}),
		);

	it("creates a bound agent through POST /agents and shows cnf on the identity", async () => {
		const keys = await newKeys();
		const res = await api("/agents", alice, {
			ownerId: "alice",
			name: "bound",
			type: "service",
			permissions: PERMS,
			cnf: { jkt: keys.jkt },
		});
		expect(res.status).toBe(201);
		const { data } = (await res.json()) as { data: { id: string; cnf?: Record<string, string> } };
		expect(data.cnf).toEqual({ jkt: keys.jkt });
		const read = await auth.agent.get(data.id);
		expect(read?.cnf).toEqual({ jkt: keys.jkt });
	});

	it("rejects a malformed cnf", async () => {
		for (const cnf of [{}, { jkt: "short" }, { jkt: 5 }, { "bad key!": "a".repeat(43) }]) {
			const res = await api("/agents", alice, {
				ownerId: "alice",
				name: "x",
				type: "service",
				permissions: PERMS,
				cnf,
			});
			expect(res.status).toBe(400);
		}
	});

	it("keeps the binding on rotate, rebinds on request, and clears it with null", async () => {
		const keys = await newKeys();
		const next = await newKeys();
		const agent = await boundAgent(auth, { jkt: keys.jkt });

		const kept = await auth.agent.rotate(agent.id);
		expect(kept.cnf).toEqual({ jkt: keys.jkt });
		expect(kept.token).not.toBe(agent.token);
		expect((await auth.authorizeByToken(agent.token, CALL)).code).toBe("invalid_token");

		const rebound = await api(`/agents/${agent.id}/rotate`, alice, { cnf: { jkt: next.jkt } });
		expect(rebound.status).toBe(200);
		const reboundBody = (await rebound.json()) as { data: { cnf: Record<string, string> } };
		expect(reboundBody.data.cnf).toEqual({ jkt: next.jkt });

		const bare = await api(`/agents/${agent.id}/rotate`, alice);
		expect(bare.status).toBe(200);
		expect(((await bare.json()) as { data: { cnf: unknown } }).data.cnf).toEqual({ jkt: next.jkt });

		const cleared = await api(`/agents/${agent.id}/rotate`, alice, { cnf: null });
		const clearedBody = (await cleared.json()) as { data: { cnf?: unknown; token: string } };
		expect(clearedBody.data.cnf).toBeUndefined();
		expect((await auth.authorizeByToken(clearedBody.data.token, CALL)).allowed).toBe(true);
	});

	it("introspects a bound token with cnf and token_type DPoP", async () => {
		const keys = await newKeys();
		const agent = await boundAgent(auth, { jkt: keys.jkt });
		const res = await api("/agents/introspect", alice, { token: agent.token });
		expect(res.status).toBe(200);
		const { data } = (await res.json()) as { data: Record<string, unknown> };
		expect(data).toMatchObject({
			active: true,
			token_type: "DPoP",
			sub: "alice",
			agent_id: agent.id,
			cnf: { jkt: keys.jkt },
		});
		expect(typeof data.exp).toBe("number");
	});

	it("introspects an unbound token as Bearer and an unknown token as inactive", async () => {
		const agent = await boundAgent(auth, undefined);
		const plain = (await (
			await api("/agents/introspect", alice, { token: agent.token })
		).json()) as {
			data: Record<string, unknown>;
		};
		expect(plain.data).toMatchObject({ active: true, token_type: "Bearer" });
		expect(plain.data.cnf).toBeUndefined();
		const unknown = (await (
			await api("/agents/introspect", alice, { token: "ta_nope" })
		).json()) as {
			data: unknown;
		};
		expect(unknown.data).toEqual({ active: false });
	});

	it("reads another owner's token as inactive", async () => {
		const agent = await boundAgent(auth, undefined);
		const res = (await (await api("/agents/introspect", bob, { token: agent.token })).json()) as {
			data: unknown;
		};
		expect(res.data).toEqual({ active: false });
	});

	it("requires a signed in caller to introspect", async () => {
		const res = await handler(
			new Request(`${BASE}/agents/introspect`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token: "ta_x" }),
			}),
		);
		expect(res.status).toBe(401);
	});
});

describe("agents.confirmation.required", () => {
	it("refuses a token that carries no binding", async () => {
		const auth = await makeAuth({ dpop: {}, required: true });
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const keys = await newKeys();
		const plain = await boundAgent(auth, undefined);
		const res = await post(handler, "Bearer", plain.token);
		expect(res.status).toBe(401);
		expect(await codeOf(res)).toBe("confirmation_required");
		const bound = await boundAgent(auth, { jkt: keys.jkt });
		expect((await post(handler, "DPoP", bound.token, await proof(keys, bound.token))).status).toBe(
			200,
		);
	});
});

describe("@glinr/theauth-client DPoP helper against the agent route", () => {
	it("binds an agent to the helper's key and calls the route, retrying once for the nonce", async () => {
		const auth = await makeAuth({ dpop: { requireNonce: true } });
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const dpop = await createDPoPClient({
			fetch: (input, init) => handler(new Request(input, init)),
		});
		const agent = await boundAgent(auth, { jkt: await dpop.thumbprint() });

		const res = await dpop.fetch(
			AUTHORIZE_URL,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(CALL),
			},
			{ accessToken: agent.token },
		);
		expect(res.status).toBe(200);
		expect(await codeOf(res)).toBe("allowed");
	});
});
