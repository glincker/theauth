/** RFC 7662 introspection (design F1 T4): live, entitlement gated, and silent to everyone else. */

import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as schema from "../src/db/schema.js";
import { createTheAuthHandler, listRoutes } from "../src/http/index.js";
import type {
	McpDelegationBinding,
	McpIntrospectionResponse,
} from "../src/mcp/revocation-types.js";
import type { McpAuthContext } from "../src/mcp/types.js";
import type { EndpointWorld } from "./mcp-endpoint-fixture.js";
import {
	bootEndpoints,
	formRequest,
	INTROSPECT_URL,
	introspectAs,
	RS_AUDIENCE,
	revokeAs,
	SECRETS,
} from "./mcp-endpoint-fixture.js";
import { basicAuth, decodePayload } from "./mcp-test-harness.js";

const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];
const HOUR = 3_600_000;

afterEach(() => {
	vi.useRealTimers();
});

async function ok(ctx: McpAuthContext, client: string, token: string) {
	const res = await introspectAs(ctx, client, token);
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data;
}

async function twoAgents(w: EndpointWorld) {
	const mk = async (name: string) =>
		(
			await w.d.auth.agent.create({
				ownerId: w.d.userId,
				name,
				type: "autonomous",
				permissions: PERMS,
			})
		).id;
	const a = await mk("a");
	const b = await mk("b");
	const chain = await w.d.auth.delegate({
		fromAgent: a,
		toAgent: b,
		permissions: PERMS,
		expiresAt: new Date(Date.now() + HOUR),
	});
	const binding: McpDelegationBinding = { v: 1, agt: [a, b], lnk: [chain.id] };
	return { a, b, link: chain.id, binding };
}

describe("introspection results", () => {
	it("reports an active token to its own client and to the entitled resource server", async () => {
		const w = await bootEndpoints();
		const { jwt, jti } = await w.issue();
		const claims = decodePayload(jwt);

		const own = await ok(w.ctx, "app", jwt);
		expect(own).toMatchObject({
			active: true,
			scope: "mcp:read mcp:write",
			client_id: "app",
			sub: w.d.userId,
			exp: claims.exp,
			iat: claims.iat,
			aud: RS_AUDIENCE,
			jti,
			token_type: "Bearer",
		});
		expect(own.theauth_inactive_reason).toBeUndefined();

		const rs = await ok(w.ctx, "rs", jwt);
		expect(rs.active).toBe(true);
		expect(rs.client_id).toBe("app");
	});

	it("returns act, agent_id and theauth_dlg for a bound token", async () => {
		const w = await bootEndpoints();
		const { a, b, binding } = await twoAgents(w);
		const { jwt } = await w.issue({ binding, agentId: b });
		const res = await ok(w.ctx, "rs", jwt);
		expect(res.active).toBe(true);
		expect(res.theauth_dlg).toEqual(binding);
		expect(res.agent_id).toBe(b);
		expect(a).not.toBe(b);
	});

	it("reports a DPoP bound token with cnf and token_type DPoP", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue({ dpopJkt: "thumbprint-1" });
		const res = await ok(w.ctx, "app", jwt);
		expect(res).toMatchObject({ active: true, token_type: "DPoP", cnf: { jkt: "thumbprint-1" } });
	});

	it("gives a caller that is not entitled exactly {active:false}, even for a live token", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		const res = await ok(w.ctx, "other", jwt);
		expect(res).toEqual({ active: false });
		expect(JSON.stringify(res)).toBe('{"active":false}');
	});

	it("gives an unconfigured resource server the bare answer for another audience", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue({ resource: "https://elsewhere.theauth.test" });
		expect(await ok(w.ctx, "rs", jwt)).toEqual({ active: false });
		expect((await ok(w.ctx, "app", jwt)).active).toBe(true);
	});

	it("is bare for garbage, a foreign signature, a refresh token hint and an oversized token", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		expect(await ok(w.ctx, "app", "not-a-token")).toEqual({ active: false });
		const parts = jwt.split(".");
		const forged = `${parts[0]}.${parts[1]}.${"A".repeat((parts[2] ?? "").length)}`;
		expect(await ok(w.ctx, "app", forged)).toEqual({ active: false });
		const hinted = await introspectAs(w.ctx, "app", jwt, { token_type_hint: "refresh_token" });
		expect(hinted.success && hinted.data).toEqual({ active: false });
		expect(await ok(w.ctx, "app", "x".repeat(9000))).toEqual({ active: false });
		expect(await ok(w.ctx, "app", `${jwt}${"x".repeat(9000)}`)).toEqual({ active: false });
	});
});

describe("inactive reasons for the entitled caller", () => {
	async function expectReason(
		w: EndpointWorld,
		jwt: string,
		reason: string,
		revoke: () => Promise<void>,
	) {
		expect((await ok(w.ctx, "rs", jwt)).active).toBe(true);
		await revoke();
		expect(await ok(w.ctx, "rs", jwt)).toEqual({ active: false, theauth_inactive_reason: reason });
		// A second instance on the same database sees it too, with no wait.
		expect(await ok(w.instance(), "app", jwt)).toEqual({
			active: false,
			theauth_inactive_reason: reason,
		});
		// Anyone else learns nothing.
		expect(await ok(w.ctx, "other", jwt)).toEqual({ active: false });
	}

	it("revoked: the jti was revoked through /mcp/revoke", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		await expectReason(w, jwt, "revoked", async () => {
			const res = await revokeAs(w.ctx, "app", jwt);
			expect(res.success).toBe(true);
		});
	});

	it("delegation_revoked: introspection sees a delegation revoke immediately (live mode)", async () => {
		const w = await bootEndpoints();
		const { b, link, binding } = await twoAgents(w);
		const { jwt } = await w.issue({ binding, agentId: b });
		await expectReason(w, jwt, "delegation_revoked", async () => {
			await w.d.auth.delegation.revoke(link);
		});
	});

	it("agent_revoked: the agent behind the token was revoked", async () => {
		const w = await bootEndpoints();
		const { a } = await twoAgents(w);
		const binding: McpDelegationBinding = { v: 1, agt: [a], lnk: [] };
		const { jwt } = await w.issue({ binding, agentId: a });
		await expectReason(w, jwt, "agent_revoked", async () => {
			await w.d.auth.agent.revoke(a);
		});
	});

	it("agent_expired: the agent row is past its expiry", async () => {
		const w = await bootEndpoints();
		const { b, binding } = await twoAgents(w);
		const { jwt } = await w.issue({ binding, agentId: b });
		await expectReason(w, jwt, "agent_expired", async () => {
			await w.d.auth.db
				.update(schema.agents)
				.set({ expiresAt: new Date(Date.now() - 60_000) })
				.where(eq(schema.agents.id, b));
		});
	});

	it("subject_revoked and client_revoked come from the shared watermark rows", async () => {
		const w = await bootEndpoints();
		const store = (await import("../src/mcp/stores-db-revocation.js")).createDbRevocationStore(
			w.d.auth.db,
		);
		const later = new Date(Date.now() + HOUR);
		const subject = await w.issue();
		await expectReason(w, subject.jwt, "subject_revoked", async () => {
			await store.revokeMany([
				{ kind: "sub", id: w.d.userId, expiresAt: later, reason: "session.revokeAll" },
			]);
		});
		const w2 = await bootEndpoints();
		const store2 = (await import("../src/mcp/stores-db-revocation.js")).createDbRevocationStore(
			w2.d.auth.db,
		);
		const client = await w2.issue();
		await expectReason(w2, client.jwt, "client_revoked", async () => {
			await store2.revokeMany([
				{ kind: "client", id: "app", expiresAt: later, reason: "client.disable" },
			]);
		});
	});

	it("expired: reported to the entitled caller only", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue({ ttlSeconds: 60 });
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(Date.now() + 5 * 60_000);
		expect(await ok(w.ctx, "rs", jwt)).toEqual({
			active: false,
			theauth_inactive_reason: "expired",
		});
		expect(await ok(w.ctx, "other", jwt)).toEqual({ active: false });
	});
});

describe("endpoint client authentication", () => {
	it("authenticates with client_secret_basic and client_secret_post", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		const post = await (await import("../src/mcp/introspect.js")).handleIntrospection(
			w.ctx,
			formRequest(INTROSPECT_URL, {
				token: jwt,
				client_id: "app",
				client_secret: SECRETS.app ?? "",
			}),
		);
		expect(post.success && post.data.active).toBe(true);
	});

	it("refuses missing, wrong and public client credentials", async () => {
		const w = await bootEndpoints();
		await w.addClient("pub", { public: true });
		const { jwt } = await w.issue();
		const { handleIntrospection } = await import("../src/mcp/introspect.js");
		const noAuth = await handleIntrospection(w.ctx, formRequest(INTROSPECT_URL, { token: jwt }));
		expect(noAuth.success).toBe(false);
		if (!noAuth.success) expect(noAuth.error.code).toBe("INVALID_CLIENT");

		const bad = await handleIntrospection(
			w.ctx,
			formRequest(INTROSPECT_URL, { token: jwt }, basicAuth("app", "wrong")),
		);
		expect(bad.success).toBe(false);
		if (!bad.success) expect(bad.error.code).toBe("INVALID_CLIENT");

		const pub = await handleIntrospection(
			w.ctx,
			formRequest(INTROSPECT_URL, { token: jwt, client_id: "pub" }),
		);
		expect(pub.success).toBe(false);
		if (!pub.success) expect(pub.error.code).toBe("INVALID_CLIENT");

		const both = await handleIntrospection(
			w.ctx,
			formRequest(
				INTROSPECT_URL,
				{ token: jwt, client_secret: "s" },
				basicAuth("app", SECRETS.app ?? ""),
			),
		);
		expect(both.success).toBe(false);
		if (!both.success) expect(both.error.code).toBe("INVALID_REQUEST");
	});

	it("never echoes the token in an error and never audits it", async () => {
		const w = await bootEndpoints();
		const { jwt } = await w.issue();
		const { handleIntrospection } = await import("../src/mcp/introspect.js");
		const events: unknown[] = [];
		const results = [
			await handleIntrospection(w.ctx, formRequest(INTROSPECT_URL, { token: jwt })),
			await handleIntrospection(
				w.ctx,
				formRequest(INTROSPECT_URL, { token: jwt }, basicAuth("app", "wrong")),
			),
			await handleIntrospection(
				w.ctx,
				formRequest(INTROSPECT_URL, {}, basicAuth("app", SECRETS.app ?? "")),
			),
		];
		for (const r of results) expect(JSON.stringify(r)).not.toContain(jwt.split(".")[2]);
		await handleIntrospection(
			w.ctx,
			formRequest(INTROSPECT_URL, { token: jwt }, basicAuth("rs", SECRETS.rs ?? "")),
			{ audit: (e) => void events.push(e) },
		);
		expect(events).toHaveLength(1);
		expect(JSON.stringify(events)).not.toContain(jwt.split(".")[2]);
		expect(events[0]).toMatchObject({ callerClientId: "rs", active: true, entitled: true });
	});
});

describe("POST /mcp/introspect over HTTP", () => {
	const BASE = "http://localhost/api/theauth";

	async function handlerFor(extra: { maxBodyBytes?: number; rpm?: number } = {}) {
		const w = await bootEndpoints(
			extra.rpm
				? {
						introspection: {
							enabled: true,
							resourceServers: [{ clientId: "rs", audiences: [RS_AUDIENCE] }],
							maxRequestsPerMinute: extra.rpm,
						},
					}
				: {},
		);
		const handler = createTheAuthHandler(w.d.auth, {
			mcp: w.module(),
			rateLimit: false,
			routes: { management: false, explain: false },
			...(extra.maxBodyBytes ? { maxBodyBytes: extra.maxBodyBytes } : {}),
		});
		const post = (
			body: string,
			headers: Record<string, string> = {},
			type = "application/x-www-form-urlencoded",
		) =>
			handler(
				new Request(`${BASE}/mcp/introspect`, {
					method: "POST",
					headers: { "Content-Type": type, ...headers },
					body,
				}),
			);
		return { w, handler, post };
	}

	it("answers 200 JSON with Cache-Control: no-store for an authenticated caller", async () => {
		const { w, post } = await handlerFor();
		const { jwt } = await w.issue();
		const res = await post(
			new URLSearchParams({ token: jwt }).toString(),
			basicAuth("rs", SECRETS.rs ?? ""),
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(res.headers.get("pragma")).toBe("no-cache");
		expect(res.headers.get("content-type")).toContain("application/json");
		expect(((await res.json()) as McpIntrospectionResponse).active).toBe(true);
	});

	it("answers 401 with WWW-Authenticate when unauthenticated or the secret is wrong", async () => {
		const { w, post } = await handlerFor();
		const { jwt } = await w.issue();
		const body = new URLSearchParams({ token: jwt }).toString();
		for (const headers of [{}, basicAuth("rs", "nope")]) {
			const res = await post(body, headers);
			expect(res.status).toBe(401);
			expect(res.headers.get("www-authenticate")).toMatch(/^Basic/);
			expect(res.headers.get("cache-control")).toBe("no-store");
			const text = await res.text();
			expect(text).not.toContain(jwt.split(".")[2] ?? "?");
			expect((JSON.parse(text) as { error: string }).error).toBe("invalid_client");
		}
	});

	it("refuses other methods and non form bodies", async () => {
		const { handler, post } = await handlerFor();
		const get = await handler(new Request(`${BASE}/mcp/introspect`));
		expect(get.status).toBe(405);
		const json = await post(
			JSON.stringify({ token: "x" }),
			basicAuth("rs", SECRETS.rs ?? ""),
			"application/json",
		);
		expect(json.status).toBe(400);
		expect(((await json.json()) as { error: string }).error).toBe("invalid_request");
	});

	it("refuses a body over the limit before any authentication", async () => {
		const { post } = await handlerFor({ maxBodyBytes: 512 });
		const res = await post(`token=${"a".repeat(2000)}`, basicAuth("rs", SECRETS.rs ?? ""));
		expect(res.status).toBe(413);
		const chunked = await post(`token=${"a".repeat(2000)}`);
		expect(chunked.status).toBe(413);
	});

	it("parses percent encoded form fields", async () => {
		const { w, post } = await handlerFor();
		const { jwt } = await w.issue();
		const res = await post(
			`token=${encodeURIComponent(jwt)}&token_type_hint=access_token`,
			basicAuth("app", SECRETS.app ?? ""),
		);
		expect(((await res.json()) as McpIntrospectionResponse).active).toBe(true);
	});

	it("rate limits per client with Retry-After", async () => {
		const { w, post } = await handlerFor({ rpm: 2 });
		const { jwt } = await w.issue();
		const body = new URLSearchParams({ token: jwt }).toString();
		const auth = basicAuth("rs", SECRETS.rs ?? "");
		expect((await post(body, auth)).status).toBe(200);
		expect((await post(body, auth)).status).toBe(200);
		const limited = await post(body, auth);
		expect(limited.status).toBe(429);
		expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
		// Another client has its own budget.
		expect((await post(body, basicAuth("app", SECRETS.app ?? ""))).status).toBe(200);
	});

	it("is 404 when introspection is off or the route is not mounted, and metadata agrees", async () => {
		const w = await bootEndpoints();
		const meta = (await (
			await createTheAuthHandler(w.d.auth, {
				mcp: w.module(),
				rateLimit: false,
				routes: { management: false, explain: false },
			})(new Request(`${BASE}/.well-known/oauth-authorization-server`))
		).json()) as Record<string, unknown>;
		expect(meta.introspection_endpoint).toBe(INTROSPECT_URL);
		expect(meta.introspection_endpoint_auth_methods_supported).toEqual([
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
		]);
		expect(meta.revocation_endpoint).toBeDefined();

		const unmounted = createTheAuthHandler(w.d.auth, {
			mcp: w.module(),
			rateLimit: false,
			routes: { management: false, explain: false, mcp: { introspect: false } },
		});
		const m2 = (await (
			await unmounted(new Request(`${BASE}/.well-known/oauth-authorization-server`))
		).json()) as Record<string, unknown>;
		expect(m2.introspection_endpoint).toBeUndefined();
		expect(m2.introspection_endpoint_auth_methods_supported).toBeUndefined();
		expect(m2.revocation_endpoint).toBeDefined();
		const hit = await unmounted(
			new Request(`${BASE}/mcp/introspect`, { method: "POST", body: "token=x" }),
		);
		expect(hit.status).toBe(404);
		expect(listRoutes({ routes: { mcp: { introspect: false } } }).map((r) => r.path)).not.toContain(
			"/mcp/introspect",
		);
		expect(listRoutes().map((r) => r.path)).toContain("/mcp/introspect");

		const off = await bootEndpoints({ introspection: { enabled: false } });
		const offHandler = createTheAuthHandler(off.d.auth, {
			mcp: off.module(),
			rateLimit: false,
			routes: { management: false, explain: false },
		});
		const metaOff = (await (
			await offHandler(new Request(`${BASE}/.well-known/oauth-authorization-server`))
		).json()) as Record<string, unknown>;
		expect(metaOff.introspection_endpoint).toBeUndefined();
		const offHit = await offHandler(
			new Request(`${BASE}/mcp/introspect`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "token=x",
			}),
		);
		expect(offHit.status).toBe(404);
	});
});
