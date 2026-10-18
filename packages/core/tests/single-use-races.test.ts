/**
 * Wave 8 review probes: single use values must be spent by exactly one of several concurrent callers.
 * On a networked database every await is a round trip, so two requests interleave freely. In memory
 * SQLite they usually run one after the other, so `lockstep` holds the first SELECT of each racer until
 * both racers have read the row. A read then unconditional write then lets both succeed. The claim must
 * be one conditional statement whose changed row count decides the winner (db/claim.ts).
 */
import BetterSqlite from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as jose from "jose";
import { describe, expect, it } from "vitest";
import { createApprovalModule } from "../src/approval/approval.js";
import { createJwtSessionModule } from "../src/auth/jwt-session.js";
import { createOidcProviderModule } from "../src/auth/oidc-provider.js";
import { createPasskeyModule, PASSKEY_ERROR, PasskeyError } from "../src/auth/passkey.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import { agents, users } from "../src/db/schema.js";

async function memoryDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db
		.insert(users)
		.values({ id: "u1", email: "u1@example.com", createdAt: now, updatedAt: now });
	return db;
}

type Thenable = { then: (f?: unknown, r?: unknown) => Promise<unknown> };

/**
 * A view of `db` whose next SELECT per racer waits until `parties` racers have issued one. Call `arm()`
 * right before the race. Everything else passes through.
 */
function lockstep(db: Database, parties = 2): { db: Database; arm: () => void } {
	let armed = false;
	let waiting: Array<() => void> = [];
	const barrier = () =>
		new Promise<void>((resolve) => {
			waiting.push(resolve);
			if (waiting.length >= parties) {
				const release = waiting;
				waiting = [];
				armed = false;
				for (const r of release) r();
			}
		});
	const wrap = <T extends object>(target: T): T =>
		new Proxy(target, {
			get(t, prop) {
				const value: unknown = Reflect.get(t, prop, t);
				if (typeof value !== "function") return value;
				if (prop === "then") {
					const then = value as Thenable["then"];
					const gate = armed ? barrier() : Promise.resolve();
					return (onF?: unknown, onR?: unknown) =>
						gate
							.then(() => then.call(t))
							.then(onF as (v: unknown) => unknown, onR as (e: unknown) => unknown);
				}
				return (...args: unknown[]) => {
					const out: unknown = (value as (...a: unknown[]) => unknown).apply(t, args);
					return out !== null && typeof out === "object" ? wrap(out) : out;
				};
			},
		});
	const view = new Proxy(db, {
		get(t, prop) {
			const value: unknown = Reflect.get(t, prop, t);
			if (prop === "select" && typeof value === "function") {
				return (...args: unknown[]) => wrap((value as (...a: unknown[]) => object).apply(t, args));
			}
			return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(t) : value;
		},
	});
	return {
		db: view,
		arm: () => {
			armed = true;
		},
	};
}

async function oidcSetup() {
	const race = lockstep(await memoryDb());
	const { privateKey } = await jose.generateKeyPair("RS256", { extractable: true });
	const mod = createOidcProviderModule(
		{ issuer: "https://auth.test.com", signingKey: privateKey as CryptoKey },
		race.db,
		async (userId) => ({ sub: userId }),
	);
	const client = await mod.registerClient({
		clientName: "Race App",
		redirectUris: ["https://app.example.com/callback"],
	});
	if (!client.success) throw new Error("registerClient failed");
	const authorized = await mod.authorize({
		clientId: client.data.clientId,
		redirectUri: "https://app.example.com/callback",
		responseType: "code",
		scope: "openid email profile",
		state: "s",
		userId: "u1",
	});
	if (!authorized.success) throw new Error("authorize failed");
	return { mod, arm: race.arm, client: client.data, code: authorized.data.code };
}

describe("OIDC provider codes and refresh tokens are single use under concurrency", () => {
	it("two concurrent exchanges of one authorization code mint one token set", async () => {
		const { mod, arm, client, code } = await oidcSetup();
		const exchange = () =>
			mod.exchangeToken({
				grantType: "authorization_code",
				code,
				redirectUri: "https://app.example.com/callback",
				clientId: client.clientId,
				clientSecret: client.clientSecret ?? undefined,
			});
		arm();
		const results = await Promise.all([exchange(), exchange()]);
		expect(results.filter((r) => r.success)).toHaveLength(1);
	});

	it("two concurrent refreshes of one refresh token mint one token set", async () => {
		const { mod, arm, client, code } = await oidcSetup();
		const first = await mod.exchangeToken({
			grantType: "authorization_code",
			code,
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		if (!first.success || !first.data.refreshToken) throw new Error("no refresh token");
		const refreshToken = first.data.refreshToken;
		const refresh = () =>
			mod.exchangeToken({
				grantType: "refresh_token",
				refreshToken,
				clientId: client.clientId,
				clientSecret: client.clientSecret ?? undefined,
			});
		// authenticateClient reads the client first, so hold the client read of both racers.
		arm();
		const results = await Promise.all([refresh(), refresh()]);
		expect(results.filter((r) => r.success)).toHaveLength(1);
	});
});

describe("JWT session refresh tokens are single use under concurrency", () => {
	it("two concurrent refreshes of one token create one session", async () => {
		const race = lockstep(await memoryDb());
		const mod = createJwtSessionModule(
			{ secret: "super-secret-key-at-least-32-chars-long!!" },
			race.db,
		);
		const created = await mod.createSession({ id: "u1" });
		if (!created.success) throw new Error("createSession failed");
		const { refreshToken } = created.data;
		race.arm();
		const results = await Promise.all([
			mod.refreshSession(refreshToken),
			mod.refreshSession(refreshToken),
		]);
		expect(results.filter((r) => r.success)).toHaveLength(1);
		const loser = results.find((r) => !r.success);
		expect(loser && !loser.success ? loser.error.code : null).toBe("REFRESH_TOKEN_USED");
	});
});

describe("passkey challenges are single use under concurrency", () => {
	it("only one of two concurrent assertions gets past the challenge", async () => {
		const sqlite = new BetterSqlite(":memory:");
		const db = drizzle(sqlite, { schema });
		await createTables(db, "sqlite");
		const mod = createPasskeyModule(
			{
				rpName: "Test",
				rpId: "example.com",
				origin: "https://example.com",
				attestation: "none",
				userVerification: "preferred",
				challengeTimeout: 60_000,
			},
			db,
		);
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-race",
			challenge: "race-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});
		const b64 = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
		const clientDataJSON = b64(
			JSON.stringify({
				type: "webauthn.get",
				challenge: "race-challenge",
				origin: "https://example.com",
			}),
		);
		const attempt = () =>
			mod
				.verifyAuthentication({
					id: "no-cred",
					rawId: "no-cred",
					type: "public-key",
					response: {
						clientDataJSON,
						authenticatorData: b64("\0".repeat(37)),
						signature: b64("\0".repeat(64)),
					},
				})
				.then(
					() => "ok",
					(err: unknown) => (err instanceof PasskeyError ? err.code : "other"),
				);
		const codes = await Promise.all([attempt(), attempt()]);
		// Exactly one caller consumed the challenge (and then failed on the unknown credential).
		expect(codes.filter((c) => c === PASSKEY_ERROR.CHALLENGE_NOT_FOUND)).toHaveLength(1);
	});
});

describe("approval decisions are first writer wins", () => {
	it("a concurrent approve cannot overwrite a deny", async () => {
		const base = await memoryDb();
		const now = new Date();
		await base.insert(agents).values({
			id: "agt-1",
			ownerId: "u1",
			name: "payer",
			type: "autonomous",
			status: "active",
			tokenHash: "h",
			tokenPrefix: "p",
			createdAt: now,
			updatedAt: now,
		});
		const race = lockstep(base);
		const approvals = createApprovalModule({}, race.db);
		const req = await approvals.request({
			agentId: "agt-1",
			userId: "u1",
			action: "execute",
			resource: "bank:transfer",
		});
		race.arm();
		const settled = await Promise.allSettled([
			approvals.deny(req.id, "u1"),
			approvals.approve(req.id, "u1"),
		]);
		expect(settled.filter((s) => s.status === "fulfilled")).toHaveLength(1);
		const winner = settled.find((s) => s.status === "fulfilled");
		const stored = await approvals.get(req.id);
		expect(winner?.status === "fulfilled" ? winner.value.status : null).toBe(stored?.status);
	});
});
