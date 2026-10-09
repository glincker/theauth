import { beforeEach, describe, expect, it } from "vitest";
import type { OAuthProvider } from "../src/auth/oauth/types.js";
import type { ResolvedUser } from "../src/auth/types.js";
import { toBase64Url } from "../src/crypto/web-crypto.js";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";
import { createVaultCipher } from "../src/vault/cipher.js";
import { tokenVault } from "../src/vault/plugin.js";
import { vaultConnections } from "../src/vault/schema.js";
import type { TokenVault } from "../src/vault/types.js";

const key = (n: number) => toBase64Url(new Uint8Array(32).fill(n));

function fakeProvider(): OAuthProvider {
	return {
		id: "github",
		name: "GitHub",
		authorizationUrl: "https://gh.example/authorize",
		tokenUrl: "https://gh.example/token",
		userInfoUrl: undefined,
		scopes: ["repo", "read:user"],
		async getAuthorizationUrl(state, verifier, redirectUri) {
			return `https://gh.example/authorize?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}&v=${verifier.length}`;
		},
		async exchangeCode() {
			return {
				accessToken: "gho_access_1",
				refreshToken: "ghr_refresh_1",
				expiresIn: 3600,
				tokenType: "bearer",
				raw: { scope: "repo read:user" },
			};
		},
		async getUserInfo() {
			return { id: "gh-42", email: undefined, raw: {} };
		},
	};
}

interface Harness {
	auth: Awaited<ReturnType<typeof createTheAuth>>;
	vault: TokenVault;
	clock: { t: number };
	refreshCalls: { n: number };
	currentUser: { u: ResolvedUser | null };
}

async function setup(keys = { k1: key(1) }, activeKeyId = "k1"): Promise<Harness> {
	const clock = { t: Date.now() };
	const refreshCalls = { n: 0 };
	const currentUser: { u: ResolvedUser | null } = { u: { id: "user-1" } };
	const fetchStub = (async () => {
		refreshCalls.n += 1;
		await new Promise((r) => setTimeout(r, 30));
		return new Response(
			JSON.stringify({
				access_token: `gho_refreshed_${refreshCalls.n}`,
				refresh_token: "ghr_refresh_2",
				expires_in: 3600,
			}),
			{ status: 200 },
		);
	}) as unknown as typeof fetch;

	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		baseUrl: "https://app.example",
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: false,
			tokenExpiry: "24h",
		},
		secondaryStorage: "memory",
		auth: { adapter: { resolveUser: async () => currentUser.u } },
		plugins: [
			tokenVault({
				keys: { keys, activeKeyId },
				providers: { github: { provider: fakeProvider(), clientId: "cid", clientSecret: "sec" } },
				fetch: fetchStub,
				now: () => clock.t,
			}),
		],
	});
	for (const id of ["user-1", "user-2"]) {
		auth.db
			.insert(schema.users)
			.values({
				id,
				email: `${id}@example.com`,
				name: id,
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
	}
	const vault = auth.plugins.getContext().tokenVault as TokenVault;
	return { auth, vault, clock, refreshCalls, currentUser };
}

async function mkAgent(
	h: Harness,
	ownerId = "user-1",
	perms = [{ resource: "vault:github", actions: ["use"] }],
) {
	return h.auth.agent.create({ ownerId, name: "a", type: "autonomous", permissions: perms });
}

async function connect(h: Harness, userId = "user-1", expiresInSeconds = 3600) {
	await h.vault.storeConnection({
		userId,
		provider: "github",
		providerAccountId: "gh-42",
		accessToken: "gho_access_1",
		refreshToken: "ghr_refresh_1",
		expiresInSeconds,
		scopes: ["repo", "read:user"],
	});
}

describe("token vault", () => {
	let h: Harness;
	beforeEach(async () => {
		h = await setup();
	});

	it("returns a token only with permission, consent and connection, and audits the read", async () => {
		const agent = await mkAgent(h);
		await connect(h);
		const input = { agentId: agent.id, userId: "user-1", provider: "github", scopes: ["repo"] };

		const noConsent = await h.vault.getAccessToken(input);
		expect(noConsent.success).toBe(false);
		if (!noConsent.success) expect(noConsent.error.code).toBe("VAULT_CONSENT_REQUIRED");

		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
		});
		const ok = await h.vault.getAccessToken(input);
		expect(ok.success).toBe(true);
		if (ok.success) {
			expect(ok.data.accessToken).toBe("gho_access_1");
			expect(ok.data.scopes).toEqual(["repo"]);
		}

		const logs = await h.auth.db.select().from(schema.auditLogs);
		const reads = logs.filter((l) => l.action === "vault.read");
		expect(reads.map((l) => l.result).sort()).toEqual(["allowed", "denied"]);
		expect(JSON.stringify(logs)).not.toContain("gho_access_1");
	});

	it("denies agents without a vault permission", async () => {
		const agent = await mkAgent(h, "user-1", [{ resource: "mcp:github:*", actions: ["read"] }]);
		await connect(h);
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
		});
		const res = await h.vault.getAccessToken({
			agentId: agent.id,
			userId: "user-1",
			provider: "github",
			scopes: ["repo"],
		});
		expect(!res.success && res.error.code).toBe("VAULT_PERMISSION_DENIED");
	});

	it("allows access through a delegation chain and stops after revoke", async () => {
		const parent = await mkAgent(h);
		const child = await mkAgent(h, "user-1", []);
		const chain = await h.auth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "vault:github", actions: ["use"] }],
			expiresAt: new Date(Date.now() + 3_600_000),
		});
		await connect(h);
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: child.id,
			provider: "github",
			scopes: ["repo"],
			delegationChainId: chain.id,
		});
		const input = { agentId: child.id, userId: "user-1", provider: "github", scopes: ["repo"] };
		expect((await h.vault.getAccessToken(input)).success).toBe(true);

		await h.auth.delegation.revoke(chain.id);
		const after = await h.vault.getAccessToken(input);
		expect(after.success).toBe(false);
		// The revoke hook already marked the consent revoked.
		expect(await h.vault.revokeForDelegation(chain.id)).toBe(0);
	});

	it("only allows downscoping, never widening", async () => {
		const agent = await mkAgent(h);
		await connect(h);
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["read:user"],
		});
		const base = { agentId: agent.id, userId: "user-1", provider: "github" };
		expect((await h.vault.getAccessToken({ ...base, scopes: ["read:user"] })).success).toBe(true);
		const wider = await h.vault.getAccessToken({ ...base, scopes: ["read:user", "repo"] });
		expect(!wider.success && wider.error.code).toBe("VAULT_CONSENT_REQUIRED");
	});

	it("honors expired and revoked consent", async () => {
		const agent = await mkAgent(h);
		await connect(h);
		const input = { agentId: agent.id, userId: "user-1", provider: "github", scopes: ["repo"] };
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
			expiresAt: new Date(h.clock.t - 1000),
		});
		expect((await h.vault.getAccessToken(input)).success).toBe(false);
		const { id } = await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
		});
		expect((await h.vault.getAccessToken(input)).success).toBe(true);
		await h.vault.revokeConsent(id, "user-1");
		expect((await h.vault.getAccessToken(input)).success).toBe(false);
	});

	it("isolates users: user-2 cannot be read with user-1's consent", async () => {
		const agent = await mkAgent(h);
		await connect(h, "user-1");
		await connect(h, "user-2");
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
		});
		const res = await h.vault.getAccessToken({
			agentId: agent.id,
			userId: "user-2",
			provider: "github",
			scopes: ["repo"],
		});
		expect(!res.success && res.error.code).toBe("VAULT_CONSENT_REQUIRED");
	});

	it("isolates tenants: a tenant agent cannot reach a tenant-less connection", async () => {
		h.auth.db
			.insert(schema.tenants)
			.values({
				id: "t1",
				name: "T1",
				slug: "t1",
				createdAt: new Date(),
				updatedAt: new Date(),
			} as never)
			.run();
		const agent = await mkAgent(h);
		await h.auth.db
			.update(schema.agents)
			.set({ tenantId: "t1" })
			.where((await import("drizzle-orm")).eq(schema.agents.id, agent.id));
		await connect(h); // stored with no tenant
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			tenantId: "t1",
			provider: "github",
			scopes: ["repo"],
		});
		const res = await h.vault.getAccessToken({
			agentId: agent.id,
			userId: "user-1",
			provider: "github",
			scopes: ["repo"],
		});
		expect(!res.success && res.error.code).toBe("VAULT_NOT_CONNECTED");
	});

	it("stores ciphertext only, and a ciphertext moved to another row fails", async () => {
		await connect(h, "user-1");
		await connect(h, "user-2");
		const rows = await h.auth.db.select().from(vaultConnections);
		for (const r of rows) {
			expect(r.accessTokenEnc.startsWith("v1.k1.")).toBe(true);
			expect(r.accessTokenEnc).not.toContain("gho_access_1");
		}
		const cipher = await createVaultCipher({ keys: { k1: key(1) }, activeKeyId: "k1" });
		const a = rows.find((r) => r.userId === "user-1");
		const b = rows.find((r) => r.userId === "user-2");
		await expect(
			cipher.decrypt(a?.accessTokenEnc ?? "", `${b?.id}|user-2||github|access`),
		).rejects.toThrow("decryption failed");
	});

	it("refreshes an expiring token once under concurrency (single flight)", async () => {
		const agent = await mkAgent(h);
		await connect(h, "user-1", 10); // inside the 60s skew
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
		});
		const input = { agentId: agent.id, userId: "user-1", provider: "github", scopes: ["repo"] };
		const results = await Promise.all(
			Array.from({ length: 6 }, () => h.vault.getAccessToken(input)),
		);
		expect(h.refreshCalls.n).toBe(1);
		for (const r of results) {
			expect(r.success && r.data.accessToken).toBe("gho_refreshed_1");
		}
	});

	it("rotates encryption keys and keeps old rows readable", async () => {
		const agent = await mkAgent(h);
		await connect(h);
		await h.vault.grantConsent({
			userId: "user-1",
			agentId: agent.id,
			provider: "github",
			scopes: ["repo"],
		});
		const before = await h.auth.db.select().from(vaultConnections);
		const sqlite = h.auth.db;

		// New process view of the same database: add k2 as active, keep k1.
		const { createTokenVault } = await import("../src/vault/vault.js");
		const { memoryStorage } = await import("../src/storage/memory.js");
		const v2 = await createTokenVault({
			db: sqlite,
			keys: { keys: { k1: key(1), k2: key(2) }, activeKeyId: "k2" },
			providers: {},
			storage: memoryStorage(),
		});
		const input = { agentId: agent.id, userId: "user-1", provider: "github", scopes: ["repo"] };
		expect((await v2.getAccessToken(input)).success).toBe(true); // old key still decrypts
		expect(await v2.rotateKeys()).toEqual({ rotated: 1 });
		expect(await v2.rotateKeys()).toEqual({ rotated: 0 });
		const after = await sqlite.select().from(vaultConnections);
		expect(after[0]?.accessTokenEnc.startsWith("v1.k2.")).toBe(true);
		expect(after[0]?.accessTokenEnc).not.toBe(before[0]?.accessTokenEnc);

		// A vault that no longer knows k1 can read the rotated row.
		const v3 = await createTokenVault({
			db: sqlite,
			keys: { keys: { k2: key(2) }, activeKeyId: "k2" },
			providers: {},
			storage: memoryStorage(),
		});
		const res = await v3.getAccessToken(input);
		expect(res.success && res.data.accessToken).toBe("gho_access_1");
	});

	it("rejects bad key config", async () => {
		await expect(createVaultCipher({ keys: { a: "short" }, activeKeyId: "a" })).rejects.toThrow(
			"32 bytes",
		);
		await expect(createVaultCipher({ keys: { a: key(1) }, activeKeyId: "b" })).rejects.toThrow(
			"activeKeyId",
		);
	});
});

describe("token vault connect flow", () => {
	it("completes start and callback with PKCE state, single use, bound to the user", async () => {
		const h = await setup();
		const [authz] = [h.auth.plugins];
		const start = await authz.handleRequest(
			new Request("https://app.example/auth/vault/connect/start", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ provider: "github" }),
			}),
		);
		expect(start?.status).toBe(200);
		const { url } = (await start?.json()) as { url: string };
		const state = new URL(url).searchParams.get("state") as string;
		expect(state.length).toBeGreaterThanOrEqual(32);

		const cb = (s: string) =>
			authz.handleRequest(
				new Request(`https://app.example/auth/vault/callback/github?code=abc&state=${s}`),
			);

		h.currentUser.u = { id: "user-2" };
		expect((await cb(state))?.status).toBe(400); // wrong user, state is burned

		h.currentUser.u = { id: "user-1" };
		expect((await cb(state))?.status).toBe(400); // replay

		const start2 = await authz.handleRequest(
			new Request("https://app.example/auth/vault/connect/start", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ provider: "github" }),
			}),
		);
		const state2 = new URL(((await start2?.json()) as { url: string }).url).searchParams.get(
			"state",
		) as string;
		const done = await cb(state2);
		expect(done?.status).toBe(200);
		const conns = await h.vault.listConnections("user-1");
		expect(conns).toHaveLength(1);
		expect(conns[0]?.scopes).toEqual(["repo", "read:user"]);
		expect(JSON.stringify(conns)).not.toContain("gho_");
	});

	it("rejects unknown providers and anonymous callers", async () => {
		const h = await setup();
		const res = await h.auth.plugins.handleRequest(
			new Request("https://app.example/auth/vault/connect/start", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ provider: "nope" }),
			}),
		);
		expect(res?.status).toBe(400);
		h.currentUser.u = null;
		const anon = await h.auth.plugins.handleRequest(
			new Request("https://app.example/auth/vault/connections"),
		);
		expect(anon?.status).toBe(401);
	});
});
