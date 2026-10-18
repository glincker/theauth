/** Revocation end to end: two MCP modules (two instances) on one database, tokens minted through the real endpoints. */
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { delegationChains } from "../src/db/schema.js";
import type { McpAuthModule, McpConfig } from "../src/mcp/types.js";
import type { DbHarness } from "./mcp-db-harness.js";
import { bootDb, finishBoot } from "./mcp-db-harness.js";
import { basicAuth, codeFlow, REDIRECT, RESOURCE, tokenRequest } from "./mcp-test-harness.js";

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";
const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];
const SECRETS = { app: "app-secret", xb: "xb-secret", rs: "rs-secret", other: "other-secret" };
const INTROSPECT_URL = "https://auth.theauth.test/api/auth/mcp/introspect";

interface World {
	d: DbHarness;
	one: McpAuthModule;
	two: McpAuthModule;
	a: string;
	b: string;
	link: string;
}

function client(id: keyof typeof SECRETS, extra: Record<string, unknown> = {}) {
	return {
		clientId: id,
		clientSecret: SECRETS[id],
		redirectUris: [REDIRECT],
		scope: "mcp:read mcp:write",
		grantTypes: ["authorization_code", "refresh_token", TE],
		...extra,
	};
}

async function world(config: Partial<McpConfig> = {}): Promise<World> {
	const base = await bootDb();
	const owner = base.userId;
	const mk = (name: string) =>
		base.auth.agent.create({ ownerId: owner, name, type: "autonomous", permissions: PERMS });
	const a = (await mk("a")).id;
	const b = (await mk("b")).id;
	const link = (
		await base.auth.delegate({
			fromAgent: a,
			toAgent: b,
			permissions: PERMS,
			expiresAt: new Date(Date.now() + 3_600_000),
		})
	).id;
	const d = finishBoot(base.auth, owner, {
		tokenExchange: { enabled: true },
		introspection: { enabled: true, resourceServers: [{ clientId: "rs", audiences: [RESOURCE] }] },
		preRegisteredClients: [
			client("app", { agentId: a }),
			client("xb", { agentId: b }),
			client("rs"),
			client("other"),
		],
		...config,
	});
	// Let the pre-registration promises settle.
	await new Promise((r) => setTimeout(r, 20));
	const two = d.another();
	await new Promise((r) => setTimeout(r, 20));
	return { d, one: d.mcp, two, a, b, link };
}

/** A token for app (agent A) through the code flow, then exchanged by xb (agent B): bound to A, B and the link. */
async function exchanged(w: World, on: McpAuthModule = w.one): Promise<string> {
	const subject = await codeFlow(
		{ mcp: on, clients: new Map(), codes: new Map(), tokens: new Map() },
		"app",
		{
			secret: SECRETS.app,
		},
	);
	const res = await on.token(
		tokenRequest(
			{
				grant_type: TE,
				subject_token: subject.access_token,
				subject_token_type: AT,
				client_id: "xb",
			},
			basicAuth("xb", SECRETS.xb),
		),
	);
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data.access_token;
}

async function codeToken(w: World): Promise<string> {
	return (
		await codeFlow({ mcp: w.one, clients: new Map(), codes: new Map(), tokens: new Map() }, "app", {
			secret: SECRETS.app,
		})
	).access_token;
}

/** Status of a protected resource call on one instance. */
async function call(mcp: McpAuthModule, token: string): Promise<number> {
	const guarded = mcp.requireMcpAuth(async () => new Response("ok"));
	const res = await guarded(
		new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } }),
	);
	return res.status;
}

describe("revocation across instances", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("live (default): a delegation revoke is seen on the very next call on both instances", async () => {
		const w = await world();
		const token = await exchanged(w);
		expect(await call(w.one, token)).toBe(200);
		expect(await call(w.two, token)).toBe(200);
		await w.d.auth.delegation.revoke(w.link);
		const res = await w.one.requireMcpAuth(async () => new Response("ok"))(
			new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } }),
		);
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
		expect(await call(w.two, token)).toBe(401);
	});

	it("cached: immediate on the revoking process, within the poll on the other, bounded by maxStalenessMs", async () => {
		const w = await world({
			revocation: { mode: "cached", maxStalenessMs: 300, pollIntervalMs: 100 },
		});
		vi.useFakeTimers({ toFake: ["Date"] });
		const token = await exchanged(w);
		expect(await call(w.one, token)).toBe(200);
		expect(await call(w.two, token)).toBe(200);

		await w.d.auth.delegation.revoke(w.link);
		// The revoking process drops its cache through the bus: no waiting.
		expect(await call(w.one, token)).toBe(401);
		// The other process still holds its verdict until its next poll sees the fingerprint change.
		vi.setSystemTime(Date.now() + 150);
		expect(await call(w.two, token)).toBe(401);
	});

	it("cached: a revoke that never reached the table still dies at maxStalenessMs", async () => {
		const w = await world({
			revocation: { mode: "cached", maxStalenessMs: 300, pollIntervalMs: 100 },
		});
		vi.useFakeTimers({ toFake: ["Date"] });
		const token = await exchanged(w);
		expect(await call(w.two, token)).toBe(200);
		// Revoke the link row directly: no bus event, no denylist row (the same as a failed row insert).
		await w.d.auth.db
			.update(delegationChains)
			.set({ status: "revoked" })
			.where(eq(delegationChains.id, w.link));
		vi.setSystemTime(Date.now() + 150);
		expect(await call(w.two, token)).toBe(200);
		vi.setSystemTime(Date.now() + 400);
		expect(await call(w.two, token)).toBe(401);
	});

	it("offline: the token keeps working until exp (documents the bound)", async () => {
		const w = await world({ revocation: { mode: "offline" } });
		const token = await exchanged(w);
		await w.d.auth.delegation.revoke(w.link);
		expect(await call(w.one, token)).toBe(200);
		expect(await call(w.two, token)).toBe(200);
	});

	it("an agent revoke kills an agent bound authorization code token on every instance", async () => {
		const w = await world();
		const token = await codeToken(w);
		expect(await call(w.one, token)).toBe(200);
		expect(await call(w.two, token)).toBe(200);
		await w.d.auth.agent.revoke(w.a);
		expect(await call(w.one, token)).toBe(401);
		expect(await call(w.two, token)).toBe(401);
	});

	it("/mcp/revoke on instance 1 is refused on instance 2", async () => {
		const w = await world();
		const token = await codeToken(w);
		expect(await call(w.two, token)).toBe(200);
		const res = await w.one.revoke(
			new Request("https://auth.theauth.test/api/auth/mcp/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					...basicAuth("app", SECRETS.app),
				},
				body: new URLSearchParams({ token, token_type_hint: "access_token" }).toString(),
			}),
		);
		expect(res.success).toBe(true);
		expect(await call(w.one, token)).toBe(401);
		expect(await call(w.two, token)).toBe(401);
	});

	it("introspection after a revoke: reason for the entitled resource server, bare false for another client", async () => {
		const w = await world();
		const token = await exchanged(w);
		const introspect = (mcp: McpAuthModule, id: "rs" | "other") =>
			mcp.introspect(
				new Request(INTROSPECT_URL, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						...basicAuth(id, SECRETS[id]),
					},
					body: new URLSearchParams({ token }).toString(),
				}),
			);
		const before = await introspect(w.two, "rs");
		expect(before.success && before.data.active).toBe(true);

		await w.d.auth.delegation.revoke(w.link);
		const rs = await introspect(w.two, "rs");
		expect(rs.success).toBe(true);
		if (rs.success) {
			expect(rs.data).toEqual({ active: false, theauth_inactive_reason: "delegation_revoked" });
		}
		const other = await introspect(w.one, "other");
		expect(other.success).toBe(true);
		if (other.success) expect(other.data).toEqual({ active: false });
	});
});
