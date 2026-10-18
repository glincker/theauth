/** Vault consent and policy-shrink grants go through the same delegator liveness filter as authorize(), and onward links built from a delegator's own permissions survive a dead inbound chain. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import type { OAuthProvider } from "../src/auth/oauth/types.js";
import { agents } from "../src/db/schema.js";
import { analyzeUsage, loadGrants } from "../src/policy-shrink/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import { tokenVault } from "../src/vault/plugin.js";
import type { TokenVault } from "../src/vault/types.js";
import { delegateTo, makeTheAuth, newAgent } from "./hook-test-utils.js";

const VAULT = [{ resource: "vault:github", actions: ["use"] }];
const GH = { action: "read", resource: "mcp:github:issues" };
const READ = [{ resource: "mcp:github:*", actions: ["read"] }];

type Break = "revoked" | "expired";

async function breakAgent(theauth: TheAuth, id: string, how: Break): Promise<void> {
	await theauth.db
		.update(agents)
		.set(how === "revoked" ? { status: "revoked" } : { expiresAt: new Date(Date.now() - 1000) })
		.where(eq(agents.id, id));
}

const provider: OAuthProvider = {
	id: "github",
	name: "GitHub",
	authorizationUrl: "https://gh.example/authorize",
	tokenUrl: "https://gh.example/token",
	userInfoUrl: undefined,
	scopes: ["repo"],
	async getAuthorizationUrl() {
		return "https://gh.example/authorize";
	},
	async exchangeCode() {
		return { accessToken: "x", tokenType: "bearer", raw: {} };
	},
	async getUserInfo() {
		return { id: "gh-42", email: undefined, raw: {} };
	},
};

async function vaultSetup() {
	const theauth = await createTheAuth({
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
		auth: { adapter: { resolveUser: async () => ({ id: "user-1" }) } },
		plugins: [
			tokenVault({
				keys: { keys: { k1: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" }, activeKeyId: "k1" },
				providers: { github: { provider, clientId: "cid", clientSecret: "sec" } },
			}),
		],
	});
	await theauth.user.create({ id: "user-1", email: "u1@example.com" });
	const vault = theauth.plugins.getContext().tokenVault as TokenVault;
	await vault.storeConnection({
		userId: "user-1",
		provider: "github",
		providerAccountId: "gh-42",
		accessToken: "gho_access_1",
		refreshToken: "ghr_refresh_1",
		expiresInSeconds: 3600,
		scopes: ["repo"],
	});
	const a = await newAgent(theauth, "a", VAULT);
	const b = await newAgent(theauth, "b", []);
	const c = await newAgent(theauth, "c", []);
	await delegateTo(theauth, a.id, b.id, VAULT);
	const bc = await delegateTo(theauth, b.id, c.id, VAULT);
	await vault.grantConsent({
		userId: "user-1",
		agentId: c.id,
		provider: "github",
		scopes: ["repo"],
		delegationChainId: bc.id,
	});
	const use = () =>
		vault.getAccessToken({ agentId: c.id, userId: "user-1", provider: "github", scopes: ["repo"] });
	return { theauth, a, b, c, use };
}

for (const how of ["revoked", "expired"] as const) {
	for (const who of ["a", "b"] as const) {
		describe(`vault use with ${who} ${how} in the chain`, () => {
			it("allows while live and refuses once the delegator is dead", async () => {
				const h = await vaultSetup();
				expect((await h.use()).success).toBe(true);
				await breakAgent(h.theauth, h[who].id, how);
				const res = await h.use();
				expect(res.success).toBe(false);
			});
		});
	}
}

describe("policy-shrink grants from dead links", () => {
	async function build() {
		const theauth = await makeTheAuth({ auditAll: true });
		const a = await newAgent(theauth, "a", READ);
		const b = await newAgent(theauth, "b", []);
		const c = await newAgent(theauth, "c", [{ resource: "tool:direct", actions: ["run"] }]);
		await delegateTo(theauth, a.id, b.id, READ);
		await delegateTo(theauth, b.id, c.id, READ);
		return { theauth, a, b, c };
	}

	for (const how of ["revoked", "expired"] as const) {
		it(`does not count grants from a link whose delegator is ${how}`, async () => {
			const { theauth, a, c } = await build();
			const before = await loadGrants(theauth.db, c.id);
			expect(before.some((g) => g.source.kind === "delegation")).toBe(true);
			await breakAgent(theauth, a.id, how);
			const after = await loadGrants(theauth.db, c.id);
			expect(after.some((g) => g.source.kind === "delegation")).toBe(false);
			const usage = await analyzeUsage(theauth.db, c.id);
			expect(usage.unused.map((p) => p.resource)).toEqual(["tool:direct"]);
		});
	}
});

describe("onward links from a delegator's own permissions", () => {
	async function build() {
		const theauth = await makeTheAuth({});
		const a = await newAgent(theauth, "a", READ);
		const b = await newAgent(theauth, "b", [{ resource: "tool:own", actions: ["run"] }]);
		const c = await newAgent(theauth, "c", []);
		await delegateTo(theauth, a.id, b.id, READ);
		const own = await delegateTo(theauth, b.id, c.id, [{ resource: "tool:own", actions: ["run"] }]);
		const inherited = await delegateTo(theauth, b.id, c.id, READ);
		return { theauth, a, b, c, own, inherited };
	}

	it("keeps the link built from direct permissions and drops the one built from the dead inbound chain", async () => {
		const { theauth, a, c } = await build();
		expect((await theauth.authorize(c.id, GH)).allowed).toBe(true);
		await breakAgent(theauth, a.id, "revoked");
		expect((await theauth.authorize(c.id, { action: "run", resource: "tool:own" })).allowed).toBe(
			true,
		);
		expect((await theauth.authorize(c.id, GH)).allowed).toBe(false);
	});

	it("keeps onward links alive only while the delegator itself is live", async () => {
		const { theauth, a, b, c } = await build();
		await breakAgent(theauth, a.id, "revoked");
		await breakAgent(theauth, b.id, "revoked");
		expect((await theauth.authorize(c.id, { action: "run", resource: "tool:own" })).allowed).toBe(
			false,
		);
	});
});
