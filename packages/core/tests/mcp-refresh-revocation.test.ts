/** Regression tests: the token endpoint honors revocations (refresh and code grants), and family revocation kills the family's live access tokens. */
import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { createDbRevocationStore } from "../src/mcp/stores-db-revocation.js";
import type { McpAuthModule } from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import { bootDb, finishBoot } from "./mcp-db-harness.js";
import {
	BASE_URL,
	basicAuth,
	codeFlow,
	REDIRECT,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const SECRET = "plain-secret";
const DAY = 86_400_000;

async function world() {
	const base = await bootDb();
	const store = createDbRevocationStore(base.auth.db);
	const d = finishBoot(base.auth, base.userId, {
		jtiDenylist: store,
		preRegisteredClients: [
			{
				clientId: "plain",
				clientSecret: SECRET,
				redirectUris: [REDIRECT],
				scope: "mcp:read mcp:write offline_access",
				grantTypes: ["authorization_code", "refresh_token"],
			},
		],
	});
	await new Promise((r) => setTimeout(r, 20));
	return { d, mcp: d.mcp, owner: base.userId, store };
}

const h = (mcp: McpAuthModule) => ({
	mcp,
	clients: new Map(),
	codes: new Map(),
	tokens: new Map(),
});
const OFFLINE = { secret: SECRET, scope: "mcp:read offline_access" };

async function call(mcp: McpAuthModule, token: string): Promise<number> {
	const guarded = mcp.requireMcpAuth(async () => new Response("ok"));
	const res = await guarded(
		new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } }),
	);
	return res.status;
}

function refresh(mcp: McpAuthModule, rt: string) {
	return mcp.token(
		tokenRequest(
			{ grant_type: "refresh_token", refresh_token: rt, client_id: "plain" },
			basicAuth("plain", SECRET),
		),
	);
}

type World = Awaited<ReturnType<typeof world>>;

async function signOutEverywhere(w: World) {
	const now = new Date();
	await w.d.auth.revocations.publish(
		{ kind: "sub", ids: [w.owner], revokedAt: now, reason: "session.revokeAll", userId: w.owner },
		[
			{
				kind: "sub",
				id: w.owner,
				expiresAt: new Date(now.getTime() + DAY),
				reason: "session.revokeAll",
			},
		],
	);
}

describe("token endpoint revocation (H1)", () => {
	it("refuses a refresh token after session.revokeAll", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		expect(await call(w.mcp, first.access_token)).toBe(200);
		await signOutEverywhere(w);
		expect(await call(w.mcp, first.access_token)).toBe(401);
		await new Promise((r) => setTimeout(r, 1100));
		const next = await refresh(w.mcp, first.refresh_token as string);
		expect(next.success).toBe(false);
		if (!next.success) expect(next.error.code).toBe("INVALID_GRANT");
	});

	it("refuses a refresh token whose client is blocked by a client watermark", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		const now = new Date();
		await w.d.auth.revocations.publish(
			{ kind: "client", ids: ["plain"], revokedAt: now, reason: "cimd.block" },
			[
				{
					kind: "client",
					id: "plain",
					expiresAt: new Date(now.getTime() + DAY),
					reason: "cimd.block",
				},
			],
		);
		await new Promise((r) => setTimeout(r, 1100));
		const next = await refresh(w.mcp, first.refresh_token as string);
		expect(next.success).toBe(false);
		if (!next.success) expect(next.error.code).toBe("INVALID_GRANT");
	});

	it("refuses a refresh token whose latest access token jti was denylisted", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		const jti = JSON.parse(
			atob((first.access_token.split(".")[1] ?? "").replace(/-/g, "+").replace(/_/g, "/")),
		).jti as string;
		await w.store.revokeMany([
			{ kind: "jti", id: jti, expiresAt: new Date(Date.now() + DAY), reason: "test" },
		]);
		const next = await refresh(w.mcp, first.refresh_token as string);
		expect(next.success).toBe(false);
	});

	it("fails closed with a server error when the revocation store errors", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		await w.d.auth.db.run(
			sql`ALTER TABLE theauth_mcp_revocations RENAME TO theauth_mcp_revocations_x`,
		);
		const next = await refresh(w.mcp, first.refresh_token as string);
		await w.d.auth.db.run(
			sql`ALTER TABLE theauth_mcp_revocations_x RENAME TO theauth_mcp_revocations`,
		);
		expect(next.success).toBe(false);
		if (!next.success) expect(next.error.code).toBe("SERVER_ERROR");
		// The refresh token was not consumed: it works once the store is back.
		const retry = await refresh(w.mcp, first.refresh_token as string);
		expect(retry.success).toBe(true);
	});

	it("still refreshes normally with no revocation", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		const next = await refresh(w.mcp, first.refresh_token as string);
		expect(next.success).toBe(true);
	});

	it("refuses an authorization code issued before a sign out everywhere", async () => {
		const w = await world();
		const verifier = generateSecureToken(43);
		const url = new URL(`${BASE_URL}/mcp/authorize`);
		const params: Record<string, string> = {
			response_type: "code",
			client_id: "plain",
			redirect_uri: REDIRECT,
			scope: "mcp:read",
			code_challenge: await computeS256Challenge(verifier),
			code_challenge_method: "S256",
			resource: RESOURCE,
		};
		for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
		const auth = await w.mcp.authorize(new Request(url));
		if (!auth.success) throw new Error(auth.error.message);
		const code = new URL(auth.data.redirectUri).searchParams.get("code") ?? "";
		await signOutEverywhere(w);
		await new Promise((r) => setTimeout(r, 1100));
		const res = await w.mcp.token(
			tokenRequest(
				{
					grant_type: "authorization_code",
					code,
					redirect_uri: REDIRECT,
					client_id: "plain",
					code_verifier: verifier,
					resource: RESOURCE,
				},
				basicAuth("plain", SECRET),
			),
		);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_GRANT");
	});
});

describe("family revocation kills live access tokens (H3)", () => {
	it("reuse detection denies the access token the thief minted", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		const rt1 = first.refresh_token as string;
		const stolen = await refresh(w.mcp, rt1);
		expect(stolen.success).toBe(true);
		if (!stolen.success) return;
		expect(await call(w.mcp, stolen.data.access_token)).toBe(200);
		expect((await refresh(w.mcp, rt1)).success).toBe(false);
		expect((await refresh(w.mcp, stolen.data.refresh_token as string)).success).toBe(false);
		expect(await call(w.mcp, stolen.data.access_token)).toBe(401);
	});

	it("explicit revoke of a refresh token denies the family's live access token", async () => {
		const w = await world();
		const first = await codeFlow(h(w.mcp), "plain", OFFLINE);
		expect(await call(w.mcp, first.access_token)).toBe(200);
		const rv = await w.mcp.revoke(
			new Request(`${BASE_URL}/mcp/revoke`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					...basicAuth("plain", SECRET),
				},
				body: new URLSearchParams({
					token: first.refresh_token as string,
					token_type_hint: "refresh_token",
				}).toString(),
			}),
		);
		expect(rv.success).toBe(true);
		expect(await call(w.mcp, first.access_token)).toBe(401);
	});
});
