import type { JWK, KeyLike } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { createExternalIssuers, validateIssuerConfig } from "../src/migrate/external-issuers.js";
import { createMemoryMigrationStore } from "../src/migrate/memory-store.js";
import { createLoginOnboarding } from "../src/migrate/onboarding.js";
import { createRollout } from "../src/migrate/rollout.js";
import { createShadow, simulatorDecider } from "../src/migrate/shadow.js";
import { formatStatus, getMigrationStatus } from "../src/migrate/status.js";

const ISS = "https://idp.example.test/";
const AUD = "api://theauth-test";
let keyA: { priv: KeyLike; jwk: JWK };
let keyB: { priv: KeyLike; jwk: JWK };

async function makeKey(kid: string) {
	const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
	const jwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };
	return { priv: privateKey, jwk };
}

async function token(
	key: { priv: KeyLike },
	kid: string,
	claims: Record<string, unknown> = {},
	over: { iss?: string; aud?: string; exp?: string | number; alg?: string } = {},
): Promise<string> {
	return new SignJWT({ email: "ada@example.test", email_verified: true, ...claims })
		.setProtectedHeader({ alg: over.alg ?? "RS256", kid })
		.setSubject("sub-1")
		.setIssuer(over.iss ?? ISS)
		.setAudience(over.aud ?? AUD)
		.setIssuedAt()
		.setExpirationTime(over.exp ?? "5m")
		.sign(key.priv);
}

function jwksFetch(getKeys: () => JWK[]) {
	const fn = vi.fn(async () => new Response(JSON.stringify({ keys: getKeys() }), { status: 200 }));
	return fn;
}

beforeAll(async () => {
	keyA = await makeKey("a");
	keyB = await makeKey("b");
});

describe("external issuers", () => {
	function issuers(getKeys: () => JWK[], extra: Record<string, unknown> = {}) {
		const fetchFn = jwksFetch(getKeys);
		let t = Date.now();
		const api = createExternalIssuers(
			[
				{
					name: "auth0",
					issuer: ISS,
					audience: AUD,
					jwksUri: `${ISS}.well-known/jwks.json`,
					fetch: fetchFn,
					...extra,
				},
			],
			{ now: () => t },
		);
		return { api, fetchFn, advance: (ms: number) => (t += ms) };
	}

	it("accepts a good token and returns the identity", async () => {
		const { api } = issuers(() => [keyA.jwk]);
		const r = await api.verify(await token(keyA, "a"));
		expect(r.success && r.data).toMatchObject({
			issuer: "auth0",
			subject: "sub-1",
			email: "ada@example.test",
			emailVerified: true,
		});
	});

	it("rejects wrong issuer, wrong audience, expired and wrong signature", async () => {
		const { api } = issuers(() => [keyA.jwk]);
		const code = async (t: string) => {
			const r = await api.verify(t);
			return r.success ? "ok" : r.error.code;
		};
		expect(await code(await token(keyA, "a", {}, { iss: "https://evil.test/" }))).toBe(
			"ISSUER_NOT_ALLOWED",
		);
		expect(await code(await token(keyA, "a", {}, { aud: "other" }))).toBe("CLAIM_REJECTED");
		expect(
			await code(await token(keyA, "a", {}, { exp: Math.floor(Date.now() / 1000) - 3600 })),
		).toBe("TOKEN_EXPIRED");
		expect(await code(await token(keyB, "a"))).toBe("SIGNATURE_INVALID");
		expect(await code("not-a-jwt")).toBe("TOKEN_MALFORMED");
	});

	it("rejects an algorithm outside the allowlist", async () => {
		const { api } = issuers(() => [keyA.jwk], { algorithms: ["ES256"] });
		const r = await api.verify(await token(keyA, "a"));
		expect(r.success).toBe(false);
	});

	it("refuses unsafe configuration", () => {
		const base = { name: "x", issuer: ISS, audience: AUD };
		expect(validateIssuerConfig({ ...base, algorithms: ["HS256"] })).toMatch(/not allowed/);
		expect(validateIssuerConfig({ ...base, algorithms: ["none"] })).toMatch(/not allowed/);
		expect(validateIssuerConfig({ ...base, audience: [] })).toMatch(/audience/);
		expect(validateIssuerConfig({ ...base, jwksUri: "http://idp.test/jwks" })).toMatch(/https/);
		expect(
			validateIssuerConfig({ ...base, jwksUri: "http://localhost/jwks", allowInsecureJwks: true }),
		).toBeNull();
		expect(() => createExternalIssuers([{ ...base, audience: "" }])).toThrow();
	});

	it("caches keys, then refetches once when a new kid appears (rotation)", async () => {
		let keys = [keyA.jwk];
		const { api, fetchFn, advance } = issuers(() => keys);
		await api.verify(await token(keyA, "a"));
		await api.verify(await token(keyA, "a"));
		expect(fetchFn).toHaveBeenCalledTimes(1);

		keys = [keyA.jwk, keyB.jwk];
		advance(31_000);
		const rotated = await api.verify(await token(keyB, "b"));
		expect(rotated.success).toBe(true);
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});

	it("does not hammer the JWKS endpoint for forged kids", async () => {
		const { api, fetchFn } = issuers(() => [keyA.jwk]);
		await api.verify(await token(keyA, "a"));
		for (let i = 0; i < 5; i++) await api.verify(await token(keyB, `forged-${i}`));
		expect(fetchFn.mock.calls.length).toBeLessThanOrEqual(2);
	});

	it("refetches after the ttl so a revoked key stops working", async () => {
		let keys = [keyA.jwk];
		const { api, advance } = issuers(() => keys, { jwksTtlSec: 60 });
		expect((await api.verify(await token(keyA, "a"))).success).toBe(true);
		keys = [keyB.jwk];
		advance(61_000);
		expect((await api.verify(await token(keyA, "a"))).success).toBe(false);
	});
});

describe("rollout", () => {
	const salt = "test-salt";
	const ids = Array.from({ length: 4000 }, (_, i) => `user-${i}`);

	it("is sticky: same user, same answer across instances and calls", async () => {
		const a = createRollout({ percent: 30, salt });
		const b = createRollout({ percent: 30, salt });
		for (const id of ids.slice(0, 200)) {
			expect(await a.assignCohort({ id })).toEqual(await b.assignCohort({ id }));
		}
	});

	it("only moves users in one direction when the percent grows", async () => {
		const lo = createRollout({ percent: 20, salt });
		const hi = createRollout({ percent: 60, salt });
		for (const id of ids.slice(0, 500)) {
			if ((await lo.assignCohort({ id })).system === "theauth") {
				expect((await hi.assignCohort({ id })).system).toBe("theauth");
			}
		}
	});

	it("distribution roughly matches the percent", async () => {
		const r = createRollout({ percent: 25, salt });
		let on = 0;
		for (const id of ids) if ((await r.assignCohort({ id })).system === "theauth") on++;
		expect(on / ids.length).toBeGreaterThan(0.21);
		expect(on / ids.length).toBeLessThan(0.29);
	});

	it("percent 0 sends everyone to the incumbent, allowlist and rules included", async () => {
		const r = createRollout({
			percent: 0,
			salt,
			allowlist: { userIds: ["vip"] },
			rules: [{ name: "all", match: () => true }],
		});
		expect(await r.assignCohort({ id: "vip" })).toEqual({
			system: "incumbent",
			cohort: "killswitch",
		});
		expect((await r.assignCohort({ id: "x" })).system).toBe("incumbent");
	});

	it("percent 100 sends everyone to theauth, and bad values fail safe", async () => {
		const all = createRollout({ percent: 100, salt });
		for (const id of ids.slice(0, 50))
			expect((await all.assignCohort({ id })).system).toBe("theauth");
		const nan = createRollout({ percent: Number.NaN, salt });
		expect((await nan.assignCohort({ id: "a" })).system).toBe("incumbent");
		const over = createRollout({ percent: 500, salt });
		expect((await over.assignCohort({ id: "a" })).system).toBe("theauth");
	});

	it("allowlist and rules apply before the percentage", async () => {
		const r = createRollout({
			percent: 1,
			salt,
			allowlist: { emails: ["Ada@Example.test"], tenants: ["t1"] },
			rules: [
				{ name: "beta", match: (u) => u.attributes?.beta === true },
				{ name: "legacy", match: (u) => u.attributes?.legacy === true, target: "incumbent" },
				{
					name: "throws",
					match: () => {
						throw new Error("x");
					},
				},
			],
		});
		expect((await r.assignCohort({ id: "1", email: "ada@example.test" })).cohort).toBe("allowlist");
		expect((await r.assignCohort({ id: "2", tenantId: "t1" })).cohort).toBe("allowlist");
		expect(await r.assignCohort({ id: "3", attributes: { beta: true } })).toEqual({
			system: "theauth",
			cohort: "rule:beta",
		});
		expect(await r.assignCohort({ id: "4", attributes: { legacy: true } })).toEqual({
			system: "incumbent",
			cohort: "rule:legacy",
		});
	});

	it("reads live config so a flag flip takes effect immediately", async () => {
		let percent = 100;
		const r = createRollout(() => ({ percent, salt }));
		expect((await r.assignCohort({ id: "u" })).system).toBe("theauth");
		percent = 0;
		expect((await r.assignCohort({ id: "u" })).system).toBe("incumbent");
	});

	it("per-route cutover honours the rollback switch", async () => {
		let percent = 50;
		const r = createRollout(() => ({ percent, salt }));
		const route = r.cutover({ "/agents": "theauth", "/login": "rollout" });
		expect((await route("/agents", { id: "u" })).system).toBe("theauth");
		expect((await route("/billing", { id: "u" })).system).toBe("incumbent");
		percent = 0;
		expect((await route("/agents", { id: "u" })).system).toBe("incumbent");
	});
});

describe("login onboarding", () => {
	function build(
		opts: {
			percent?: number;
			jit?: boolean;
			link?: boolean;
			store?: ReturnType<typeof createMemoryMigrationStore>;
		} = {},
	) {
		const store = opts.store ?? createMemoryMigrationStore();
		const issuers = createExternalIssuers([
			{
				name: "auth0",
				issuer: ISS,
				audience: AUD,
				jwksUri: `${ISS}jwks`,
				fetch: jwksFetch(() => [keyA.jwk]),
			},
		]);
		const rollout = createRollout({ percent: opts.percent ?? 100, salt: "s" });
		const hook = createLoginOnboarding({
			issuers,
			store,
			rollout,
			jit: opts.jit ?? true,
			linkVerifiedEmail: opts.link,
		});
		return { store, hook };
	}

	it("creates the account just in time and migrates a supplied password", async () => {
		const { store, hook } = build();
		const o = await hook.onLogin({ token: await token(keyA, "a"), password: "typed-at-login" });
		expect(o).toMatchObject({ servedBy: "theauth", action: "created", passwordMigrated: true });
		expect(store.users.size).toBe(1);
		const again = await hook.onLogin({ token: await token(keyA, "a") });
		expect(again.action).toBe("existing");
		expect(store.users.size).toBe(1);
		const status = await getMigrationStatus(store);
		expect(status.migrated).toBe(1);
		expect(status.bySource.auth0?.migrated).toBe(1);
	});

	it("percent 0 leaves everyone on the incumbent and creates nothing", async () => {
		const { store, hook } = build({ percent: 0 });
		const o = await hook.onLogin({ token: await token(keyA, "a") });
		expect(o).toMatchObject({ servedBy: "incumbent", action: "skipped", cohort: "killswitch" });
		expect(store.users.size).toBe(0);
	});

	it("does nothing without the jit opt-in", async () => {
		const { store, hook } = build({ jit: false });
		const o = await hook.onLogin({ token: await token(keyA, "a") });
		expect(o).toMatchObject({ action: "skipped", errorCode: "JIT_DISABLED" });
		expect(store.users.size).toBe(0);
	});

	it("falls back to the incumbent when the token is bad", async () => {
		const { hook } = build();
		const o = await hook.onLogin({ token: await token(keyA, "a", {}, { aud: "nope" }) });
		expect(o).toMatchObject({
			servedBy: "incumbent",
			action: "failed",
			errorCode: "CLAIM_REJECTED",
		});
	});

	it("falls back to the incumbent when the store throws, without throwing itself", async () => {
		const store = createMemoryMigrationStore();
		store.createUser = async () => {
			throw new Error("db down");
		};
		const { hook } = build({ store });
		const o = await hook.onLogin({ token: await token(keyA, "a") });
		expect(o).toMatchObject({
			servedBy: "incumbent",
			action: "failed",
			errorCode: "ONBOARDING_ERROR",
		});
		expect((await getMigrationStatus(store)).failed).toBe(1);
	});

	it("does not take over an existing account by email unless opted in and verified", async () => {
		const seeded = createMemoryMigrationStore();
		await seeded.createUser(
			{
				externalId: "old",
				email: "ada@example.test",
				emailVerified: true,
				name: null,
				linkedAccounts: [],
				metadata: {},
			},
			"other",
		);
		const blocked = await build({ store: seeded }).hook.onLogin({ token: await token(keyA, "a") });
		expect(blocked).toMatchObject({
			action: "failed",
			errorCode: "EMAIL_CONFLICT",
			servedBy: "incumbent",
		});

		const linked = await build({ store: seeded, link: true }).hook.onLogin({
			token: await token(keyA, "a"),
		});
		expect(linked.action).toBe("linked");
		const unverified = createMemoryMigrationStore();
		await unverified.createUser(
			{
				externalId: "old",
				email: "ada@example.test",
				emailVerified: true,
				name: null,
				linkedAccounts: [],
				metadata: {},
			},
			"other",
		);
		const refused = await build({ store: unverified, link: true }).hook.onLogin({
			token: await token(keyA, "a", { email_verified: false }),
		});
		expect(refused.errorCode).toBe("EMAIL_CONFLICT");
	});

	it("a throwing onOutcome callback does not affect the result", async () => {
		const store = createMemoryMigrationStore();
		const issuers = createExternalIssuers([
			{
				name: "auth0",
				issuer: ISS,
				audience: AUD,
				jwksUri: `${ISS}jwks`,
				fetch: jwksFetch(() => [keyA.jwk]),
			},
		]);
		const hook = createLoginOnboarding({
			issuers,
			store,
			rollout: createRollout({ percent: 100, salt: "s" }),
			jit: true,
			onOutcome: () => {
				throw new Error("log sink down");
			},
		});
		expect((await hook.onLogin({ token: await token(keyA, "a") })).action).toBe("created");
	});
});

describe("shadow mode", () => {
	it("returns the incumbent decision and reports differences", async () => {
		const diffs: unknown[] = [];
		const shadow = createShadow<{ route: string }>({
			incumbent: async () => "allow",
			theauth: async (i) => (i.route === "/x" ? "deny" : "allow"),
			label: (i) => i.route,
			onDifference: (d) => {
				diffs.push(d);
			},
		});
		expect(await shadow.evaluate({ route: "/ok" })).toEqual({
			decision: "allow",
			compared: true,
			differs: false,
		});
		expect(await shadow.evaluate({ route: "/x" })).toEqual({
			decision: "allow",
			compared: true,
			differs: true,
		});
		expect(diffs).toEqual([{ label: "/x", incumbent: "allow", theauth: "deny" }]);
		expect(shadow.stats()).toEqual({ compared: 2, differences: 1, errors: 0 });
	});

	it("never enforces the shadow side, even when theauth errors or the logger throws", async () => {
		const shadow = createShadow<string>({
			incumbent: async () => "deny",
			theauth: async () => {
				throw new Error("sim down");
			},
			label: (s) => s,
			onDifference: () => {
				throw new Error("sink down");
			},
		});
		const r = await shadow.evaluate("r");
		expect(r.decision).toBe("deny");
		expect(shadow.stats().errors).toBe(1);
	});

	it("uses the simulator as the theauth side", async () => {
		const simulator = {
			simulate: vi.fn(async () => ({
				success: true as const,
				data: { decision: "needs_approval" as const, allowed: false, reasons: [], trace: [] },
			})),
		};
		const decide = simulatorDecider<{ a: string }>(simulator, (i) => ({
			agentId: "ag",
			action: i.a,
			resource: "tool:x",
		}));
		expect(await decide({ a: "read" })).toBe("needs_approval");
		expect(simulator.simulate).toHaveBeenCalledWith({
			agentId: "ag",
			action: "read",
			resource: "tool:x",
		});
	});
});

describe("status", () => {
	it("counts by source and cohort and carries no personal data", async () => {
		const store = createMemoryMigrationStore();
		const t = (n: number) => new Date(2026, 0, 1, 0, 0, n);
		await store.recordMigration({
			userId: "u1",
			source: "auth0",
			status: "pending",
			cohort: null,
			errorCode: null,
			at: t(1),
		});
		await store.recordMigration({
			userId: "u1",
			source: "auth0",
			status: "migrated",
			cohort: "percent",
			errorCode: null,
			at: t(2),
		});
		await store.recordMigration({
			userId: "u2",
			source: "auth0",
			status: "pending",
			cohort: null,
			errorCode: null,
			at: t(1),
		});
		await store.recordMigration({
			userId: null,
			source: "keycloak",
			status: "failed",
			cohort: "percent",
			errorCode: "NO_EMAIL",
			at: t(3),
		});
		const s = await getMigrationStatus(store, t(9));
		expect(s).toMatchObject({
			total: 3,
			migrated: 1,
			pending: 1,
			failed: 1,
			percentMigrated: 33.3,
		});
		expect(s.bySource.auth0).toEqual({ migrated: 1, pending: 1, failed: 0 });
		expect(s.byCohort).toEqual({ percent: 1 });
		expect(s.failuresByCode).toEqual({ NO_EMAIL: 1 });
		const out = JSON.stringify(s) + formatStatus(s);
		expect(out).not.toContain("u1");
		expect(out).not.toContain("@");
	});
});
