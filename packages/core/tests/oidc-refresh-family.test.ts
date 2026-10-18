/** OIDC refresh token reuse revokes the whole family (RFC 9700 section 4.14.2). */
import * as jose from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import type { OidcProviderModule } from "../src/auth/oidc-provider.js";
import { createOidcProviderModule } from "../src/auth/oidc-provider.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { oidcRefreshTokens } from "../src/db/schema.js";

const REDIRECT = "https://app.example.com/callback";

describe("OIDC refresh token families", () => {
	let db: Database;
	let mod: OidcProviderModule;
	let clientId: string;
	let clientSecret: string | undefined;

	beforeEach(async () => {
		db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const pair = await jose.generateKeyPair("RS256", { extractable: true });
		mod = createOidcProviderModule(
			{ issuer: "https://auth.test.com", signingKey: pair.privateKey as CryptoKey },
			db,
			async (userId) => ({ sub: userId }),
		);
		const reg = await mod.registerClient({ clientName: "App", redirectUris: [REDIRECT] });
		if (!reg.success) throw new Error("registerClient failed");
		clientId = reg.data.clientId;
		clientSecret = reg.data.clientSecret ?? undefined;
	});

	async function login(): Promise<string> {
		const auth = await mod.authorize({
			clientId,
			redirectUri: REDIRECT,
			responseType: "code",
			scope: "openid",
			state: "s",
			userId: "user-1",
		});
		if (!auth.success) throw new Error("authorize failed");
		const tok = await mod.exchangeToken({
			grantType: "authorization_code",
			code: auth.data.code,
			redirectUri: REDIRECT,
			clientId,
			clientSecret,
		});
		if (!tok.success) throw new Error("exchange failed");
		return tok.data.refreshToken;
	}

	const refresh = (refreshToken: string) =>
		mod.exchangeToken({ grantType: "refresh_token", refreshToken, clientId, clientSecret });

	it("reusing a rotated token revokes the newest token of the same family", async () => {
		const t0 = await login();
		const r1 = await refresh(t0);
		if (!r1.success) throw new Error("first refresh failed");
		const t1 = r1.data.refreshToken;
		const r2 = await refresh(t1);
		if (!r2.success) throw new Error("second refresh failed");
		const t2 = r2.data.refreshToken;

		// An attacker replays t0, which was rotated two steps ago.
		const replay = await refresh(t0);
		expect(replay.success).toBe(false);

		// The legitimate holder of t2 is cut off too.
		const after = await refresh(t2);
		expect(after.success).toBe(false);
		if (!after.success) expect(after.error.code).toBe("REFRESH_TOKEN_REVOKED");
	});

	it("does not touch another login of the same user and client", async () => {
		const a = await login();
		const b = await login();
		const ra = await refresh(a);
		if (!ra.success) throw new Error("refresh a failed");
		expect((await refresh(a)).success).toBe(false); // reuse in family A
		expect((await refresh(ra.data.refreshToken)).success).toBe(false);
		expect((await refresh(b)).success).toBe(true); // family B lives
	});

	it("rotated tokens keep the family id of the first token", async () => {
		const t0 = await login();
		const r1 = await refresh(t0);
		if (!r1.success) throw new Error("refresh failed");
		const rows = await db.select().from(oidcRefreshTokens);
		expect(rows).toHaveLength(2);
		expect(new Set(rows.map((r) => r.familyId)).size).toBe(1);
		expect(rows[0]?.familyId).toBeTruthy();
	});

	it("a replay after a family wipe stays a plain failure", async () => {
		const t0 = await login();
		await refresh(t0);
		await refresh(t0);
		const again = await refresh(t0);
		expect(again.success).toBe(false);
	});

	it("legacy rows without a family fall back to user and client", async () => {
		const t0 = await login();
		const other = await login();
		await db.update(oidcRefreshTokens).set({ familyId: null });
		const r1 = await refresh(t0);
		if (!r1.success) throw new Error("refresh failed");
		expect((await refresh(t0)).success).toBe(false);
		expect((await refresh(other)).success).toBe(false);
	});
});
