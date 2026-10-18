/** Mint time delegation binding (design F1 T2): RFC 8693 exchange signs `theauth_dlg` naming the exact live links and agents, and the child never outlives any of them. */
import { describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import { attachBindingStore } from "../src/mcp/binding.js";
import { attachFreshnessDeps } from "../src/mcp/freshness.js";
import { handleTokenExchangeGrant } from "../src/mcp/grant-token-exchange.js";
import { createInMemoryJtiDenylist } from "../src/mcp/memory-stores.js";
import type {
	McpBindingAgent,
	McpBindingStore,
	McpDelegationBinding,
	McpLiveLink,
} from "../src/mcp/revocation-types.js";
import { createDbBindingStore } from "../src/mcp/stores-db-binding.js";
import { issueAccessTokenJwt } from "../src/mcp/token-issue.js";
import type { McpActorAgentResolver, McpAuthContext, McpClient } from "../src/mcp/types.js";
import { hashClientSecret } from "../src/mcp/utils.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import { BASE_URL, decodePayload, ISSUER, RESOURCE, SECRET } from "./mcp-test-harness.js";

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";
const USER = "user-1";
const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];
const HOUR = 3_600_000;

interface Fixture {
	ctx: McpAuthContext;
	clients: Map<string, McpClient>;
}

interface CtxOptions {
	requireBoundChain?: boolean;
	resolveActorAgentId?: McpActorAgentResolver;
	accessTokenTtl?: number;
}

function makeCtx(store: McpBindingStore | undefined, opts: CtxOptions = {}): Fixture {
	const clients = new Map<string, McpClient>();
	const ctx: McpAuthContext = {
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SECRET,
			resource: RESOURCE,
			scopes: ["mcp:read", "mcp:write"],
			accessTokenTtl: opts.accessTokenTtl ?? 3600,
			refreshTokenTtl: 86400,
			refreshTokenAbsoluteTtl: 864000,
			codeTtl: 600,
			jtiDenylist: createInMemoryJtiDenylist(),
			tokenExchange: { enabled: true, maxChainDepth: 5 },
			revocation: { requireBoundChain: opts.requireBoundChain ?? false },
			...(opts.resolveActorAgentId ? { resolveActorAgentId: opts.resolveActorAgentId } : {}),
		},
		storeClient: async (c) => {
			clients.set(c.clientId, c);
		},
		findClient: async (id) => clients.get(id) ?? null,
		storeAuthorizationCode: async () => {},
		consumeAuthorizationCode: async () => null,
		storeToken: async () => {},
		findTokenByRefreshToken: async () => null,
		revokeToken: async () => {},
		resolveUserId: async () => USER,
	};
	if (store) {
		attachBindingStore(ctx, store);
		attachFreshnessDeps(ctx, { bindings: store });
	}
	return { ctx, clients };
}

async function addClient(f: Fixture, clientId: string, agentId?: string): Promise<void> {
	const now = new Date();
	f.clients.set(clientId, {
		clientId,
		clientSecret: await hashClientSecret("s"),
		clientName: null,
		clientUri: null,
		logoUri: null,
		redirectUris: [],
		grantTypes: [TE, "authorization_code"],
		responseTypes: ["code"],
		tokenEndpointAuthMethod: "client_secret_basic",
		scope: null,
		contacts: null,
		tosUri: null,
		policyUri: null,
		softwareId: null,
		softwareVersion: null,
		clientType: "confidential",
		disabled: false,
		userId: null,
		agentId: agentId ?? null,
		createdAt: now,
		updatedAt: now,
	});
}

/** A user token issued to `clientId` (bound clients get `agt: [agent]`). */
async function subjectToken(f: Fixture, clientId: string, ttlSeconds?: number): Promise<string> {
	const out = await issueAccessTokenJwt(
		f.ctx,
		USER,
		clientId,
		["mcp:read", "mcp:write"],
		RESOURCE,
		null,
		{
			...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
		},
	);
	return out.jwt;
}

async function exchange(f: Fixture, token: string, clientId: string) {
	return handleTokenExchangeGrant(
		f.ctx,
		{ client_id: clientId, subject_token: token, subject_token_type: AT },
		{ clientSecret: "s", assertionVerified: false },
		null,
	);
}

async function exchangeOk(f: Fixture, token: string, clientId: string): Promise<string> {
	const res = await exchange(f, token, clientId);
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	expect(res.data.refresh_token).toBeUndefined();
	return res.data.access_token;
}

async function bootAuth(): Promise<TheAuth> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 50, defaultPermissions: [], tokenExpiry: "24h" },
	});
	auth.db
		.insert(schema.users)
		.values({
			id: USER,
			email: "u@example.com",
			name: "U",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return auth;
}

async function agent(auth: TheAuth, name: string, expiresAt?: Date): Promise<string> {
	const a = await auth.agent.create({
		ownerId: USER,
		name,
		type: "autonomous",
		permissions: PERMS,
		...(expiresAt ? { expiresAt } : {}),
	});
	return a.id;
}

async function link(auth: TheAuth, from: string, to: string, ms = HOUR): Promise<string> {
	const chain = await auth.delegate({
		fromAgent: from,
		toAgent: to,
		permissions: PERMS,
		expiresAt: new Date(Date.now() + ms),
	});
	return chain.id;
}

const dlg = (token: string) => decodePayload(token).theauth_dlg as McpDelegationBinding | undefined;
const exp = (token: string) => decodePayload(token).exp as number;

/** Agents A, B, C; clients app (A), xb (B), xc (C), xd (unbound). */
async function world(opts: CtxOptions = {}) {
	const auth = await bootAuth();
	const store = createDbBindingStore(auth.db);
	const f = makeCtx(store, opts);
	const a = await agent(auth, "a");
	const b = await agent(auth, "b");
	const c = await agent(auth, "c");
	await addClient(f, "app", a);
	await addClient(f, "xb", b);
	await addClient(f, "xc", c);
	await addClient(f, "xd");
	return { auth, store, f, a, b, c };
}

describe("token exchange binds the child to its delegation", () => {
	it("signs theauth_dlg next to act, with no refresh token", async () => {
		const { auth, f, a, b } = await world();
		const ab = await link(auth, a, b);
		const subject = await subjectToken(f, "app");
		expect(dlg(subject)).toEqual({ v: 1, agt: [a], lnk: [] });
		const child = await exchangeOk(f, subject, "xb");
		const payload = decodePayload(child);
		expect(payload.theauth_dlg).toEqual({ v: 1, agt: [a, b], lnk: [ab] });
		expect(payload.act).toEqual({ sub: "xb", client_id: "xb" });
		expect(payload.sub).toBe(USER);
	});

	it("caps exp at the link expiry", async () => {
		const { auth, f, a, b } = await world();
		const ab = await link(auth, a, b, 600_000);
		const row = auth.db
			.select()
			.from(schema.delegationChains)
			.all()
			.find((r) => r.id === ab);
		const child = await exchangeOk(f, await subjectToken(f, "app"), "xb");
		const linkExp = Math.floor((row?.expiresAt.getTime() ?? 0) / 1000);
		expect(exp(child)).toBeLessThanOrEqual(linkExp);
		expect(exp(child)).toBeGreaterThan(linkExp - 5);
	});

	it("caps exp at the agent expiry", async () => {
		const { auth, f, a } = await world();
		const short = await agent(auth, "short", new Date(Date.now() + 300_000));
		await addClient(f, "xs", short);
		await link(auth, a, short);
		const child = await exchangeOk(f, await subjectToken(f, "app"), "xs");
		const agentExp = Math.floor((Date.now() + 300_000) / 1000);
		expect(exp(child)).toBeLessThanOrEqual(agentExp);
		expect(exp(child)).toBeGreaterThan(agentExp - 5);
	});

	it("caps exp at the parent token expiry", async () => {
		const { auth, f, a, b } = await world();
		await link(auth, a, b);
		const subject = await subjectToken(f, "app", 120);
		const child = await exchangeOk(f, subject, "xb");
		expect(exp(child)).toBeLessThanOrEqual(exp(subject));
	});

	it("refuses when the link between consecutive agents is missing", async () => {
		const { f } = await world();
		const res = await exchange(f, await subjectToken(f, "app"), "xb");
		expect(res.success).toBe(false);
		if (!res.success) {
			expect(res.error.code).toBe("INVALID_GRANT");
			expect(res.error.message).toMatch(/No live delegation/);
		}
	});

	it("refuses when the actor mapper throws", async () => {
		const { auth, f, a, b } = await world({
			resolveActorAgentId: async (actor) => {
				if (actor.sub === "xb") throw new Error("mapper down");
				return undefined;
			},
		});
		await link(auth, a, b);
		const res = await exchange(f, await subjectToken(f, "app"), "xb");
		expect(res.success).toBe(false);
		if (!res.success) {
			expect(res.error.code).toBe("INVALID_GRANT");
			expect(res.error.message).toMatch(/could not be mapped/);
		}
	});

	it("mints unbound without agents, and refuses that under requireBoundChain", async () => {
		const loose = await world();
		await addClient(loose.f, "plain");
		const child = await exchangeOk(loose.f, await subjectToken(loose.f, "plain"), "xd");
		expect(dlg(child)).toBeUndefined();
		expect(decodePayload(child).act).toEqual({ sub: "xd", client_id: "xd" });

		const strict = await world({ requireBoundChain: true });
		await addClient(strict.f, "plain");
		const res = await exchange(strict.f, await subjectToken(strict.f, "plain"), "xd");
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_GRANT");
	});

	it("refuses under requireBoundChain when no binding store is attached", async () => {
		const f = makeCtx(undefined, { requireBoundChain: true });
		await addClient(f, "plain");
		await addClient(f, "xd");
		const res = await exchange(f, await subjectToken(f, "plain"), "xd");
		expect(res.success).toBe(false);
	});

	it("binds two links for A to B to C", async () => {
		const { auth, f, a, b, c } = await world();
		const ab = await link(auth, a, b);
		const bc = await link(auth, b, c);
		const first = await exchangeOk(f, await subjectToken(f, "app"), "xb");
		const second = await exchangeOk(f, first, "xc");
		expect(dlg(second)).toEqual({ v: 1, agt: [a, b, c], lnk: [ab, bc] });
		expect(exp(second)).toBeLessThanOrEqual(exp(first));
	});

	it("revoking A to B kills the C token through the cascade", async () => {
		const { auth, store, f, a, b, c } = await world();
		const ab = await link(auth, a, b);
		await link(auth, b, c);
		const first = await exchangeOk(f, await subjectToken(f, "app"), "xb");
		const second = await exchangeOk(f, first, "xc");
		const bound = dlg(second) as McpDelegationBinding;
		expect((await store.check(bound, new Date())).live).toBe(true);

		await auth.delegation.revoke(ab);

		const verdict = await store.check(bound, new Date());
		expect(verdict.live).toBe(false);
		if (!verdict.live) expect(verdict.reason).toBe("delegation_revoked");
		// No new child can be minted from either token, nor a fresh B to C hop.
		expect((await exchange(f, second, "xd")).success).toBe(false);
		expect((await exchange(f, first, "xc")).success).toBe(false);
		expect(await store.findLiveLink(b, c, new Date())).toBeNull();
	});
});

/** Seeded PRNG so a failure reproduces. */
function rng(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (s * 1664525 + 1013904223) >>> 0;
		return s / 0x1_0000_0000;
	};
}

/** In-memory binding store over plain maps (all agents active, all links live). */
function fakeStore(
	agentExp: Map<string, Date | null>,
	links: Map<string, { id: string; expiresAt: Date }>,
): McpBindingStore {
	return {
		async agents(ids) {
			const out = new Map<string, McpBindingAgent>();
			for (const id of ids) {
				if (agentExp.has(id)) {
					out.set(id, { status: "active", expiresAt: agentExp.get(id) ?? null, ownerId: USER });
				}
			}
			return out;
		},
		async findLiveLink(from, to, now): Promise<McpLiveLink | null> {
			const l = links.get(`${from}>${to}`);
			return l && l.expiresAt > now ? l : null;
		},
		async check(binding, now) {
			let until = new Date(8_640_000_000_000_000);
			for (const id of binding.agt) {
				if (!agentExp.has(id)) return { live: false, reason: "agent_revoked", id };
				const e = agentExp.get(id) ?? null;
				if (e && e <= now) return { live: false, reason: "agent_expired", id };
				if (e && e < until) until = e;
			}
			for (const [i, id] of binding.lnk.entries()) {
				const l = links.get(`${binding.agt[i]}>${binding.agt[i + 1]}`);
				if (!l || l.id !== id) return { live: false, reason: "invalid", id };
				if (l.expiresAt <= now) return { live: false, reason: "delegation_expired", id };
				if (l.expiresAt < until) until = l.expiresAt;
			}
			return { live: true, validUntil: until };
		},
	};
}

describe("exp property", () => {
	it("no minted token outlives any bound link or agent across 200 random chains", async () => {
		const rand = rng(0xf1);
		const agentExp = new Map<string, Date | null>();
		const links = new Map<string, { id: string; expiresAt: Date }>();
		const f = makeCtx(fakeStore(agentExp, links), { accessTokenTtl: 3600 });
		const secs = () => 5 + Math.floor(rand() * 7200);
		let minted = 0;
		for (let n = 0; n < 200; n++) {
			const now = Date.now();
			const hops = 1 + Math.floor(rand() * 4);
			const ids = Array.from({ length: hops }, (_, i) => `ag-${n}-${i}`);
			for (const [i, id] of ids.entries()) {
				agentExp.set(id, rand() < 0.3 ? null : new Date(now + secs() * 1000));
				await addClient(f, `cl-${n}-${i}`, id);
				if (i > 0) {
					links.set(`${ids[i - 1]}>${id}`, {
						id: `ln-${n}-${i}`,
						expiresAt: new Date(now + secs() * 1000),
					});
				}
			}
			let token = await subjectToken(f, `cl-${n}-0`, secs());
			for (let i = 1; i < hops; i++) {
				const parentExp = exp(token);
				token = await exchangeOk(f, token, `cl-${n}-${i}`);
				minted++;
				const binding = dlg(token) as McpDelegationBinding;
				expect(binding.agt).toEqual(ids.slice(0, i + 1));
				const e = exp(token) * 1000;
				expect(e).toBeLessThanOrEqual(parentExp * 1000);
				for (const id of binding.agt) {
					const ae = agentExp.get(id);
					if (ae) expect(e).toBeLessThanOrEqual(ae.getTime());
				}
				for (const [j, id] of binding.lnk.entries()) {
					const l = links.get(`${binding.agt[j]}>${binding.agt[j + 1]}`);
					expect(l?.id).toBe(id);
					expect(e).toBeLessThanOrEqual(l?.expiresAt.getTime() ?? 0);
				}
			}
		}
		expect(minted).toBeGreaterThan(200);
	});
});
