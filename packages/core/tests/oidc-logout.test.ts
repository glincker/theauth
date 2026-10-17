/** Tests for OIDC provider logout wiring and the RP-side session revoker. */

import * as jose from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { createBackChannelLogoutReceiver } from "../src/auth/federated-logout.js";
import { createSessionRevoker } from "../src/auth/federated-logout-sessions.js";
import type { OidcProviderModule } from "../src/auth/oidc-provider.js";
import { createOidcProviderModule } from "../src/auth/oidc-provider.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import type { SessionManager } from "../src/session/session.js";
import { createSessionManager } from "../src/session/session.js";

const ISSUER = "https://auth.test.com";
const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

interface Delivery {
	url: string;
	token: string;
}

async function setup(options: { failDelivery?: boolean } = {}) {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db
		.insert(users)
		.values({ id: "user-1", email: "u1@example.com", createdAt: now, updatedAt: now });

	const pair = await jose.generateKeyPair("RS256", { extractable: true });
	const deliveries: Delivery[] = [];
	const fetchImpl: typeof fetch = async (input, init) => {
		const body = new URLSearchParams(String(init?.body ?? ""));
		deliveries.push({ url: String(input), token: body.get("logout_token") ?? "" });
		if (options.failDelivery) throw new Error("network down");
		return new Response(null, { status: 200 });
	};

	let providerRef: OidcProviderModule | undefined;
	const sessions = createSessionManager(
		{
			secret: SECRET,
			onRevoke: async (revoked) => {
				await providerRef?.logout?.handleSessionsRevoked(revoked);
			},
		},
		db,
	);

	const provider = createOidcProviderModule(
		{
			issuer: ISSUER,
			signingKey: pair.privateKey as CryptoKey,
			logout: {
				sessionManager: sessions,
				allowInsecureBackchannel: true,
				fetchImpl,
				defaultRedirectUri: "https://auth.test.com/signed-out",
			},
		},
		db,
		async (userId) => ({ sub: userId }),
	);
	providerRef = provider;
	return { db, provider, sessions, deliveries, publicKey: pair.publicKey };
}

async function login(provider: OidcProviderModule, sessions: SessionManager, sessionId?: string) {
	const reg = await provider.registerClient({
		clientName: "RP",
		redirectUris: ["https://rp.example.com/cb"],
		postLogoutRedirectUris: ["https://rp.example.com/bye"],
		backchannelLogoutUri: "https://rp.example.com/backchannel",
	});
	if (!reg.success) throw new Error(reg.error.message);
	const session = sessionId ?? (await sessions.create("user-1")).session.id;
	const auth = await provider.authorize({
		clientId: reg.data.clientId,
		redirectUri: "https://rp.example.com/cb",
		responseType: "code",
		scope: "openid",
		userId: "user-1",
		sessionId: session,
	});
	if (!auth.success) throw new Error(auth.error.message);
	const tokens = await provider.exchangeToken({
		grantType: "authorization_code",
		code: auth.data.code,
		redirectUri: "https://rp.example.com/cb",
		clientId: reg.data.clientId,
		...(reg.data.clientSecret && { clientSecret: reg.data.clientSecret }),
	});
	if (!tokens.success) throw new Error(tokens.error.message);
	return { client: reg.data, sessionId: session, tokens: tokens.data };
}

describe("OIDC provider logout wiring", () => {
	let ctx: Awaited<ReturnType<typeof setup>>;

	beforeEach(async () => {
		ctx = await setup();
	});

	it("is off by default", async () => {
		const pair = await jose.generateKeyPair("RS256", { extractable: true });
		const plain = createOidcProviderModule(
			{ issuer: ISSUER, signingKey: pair.privateKey as CryptoKey },
			ctx.db,
			async (userId) => ({ sub: userId }),
		);
		const doc = plain.getDiscoveryDocument();
		expect(doc.end_session_endpoint).toBeUndefined();
		expect(doc.backchannel_logout_supported).toBeUndefined();
		expect(plain.logout).toBeUndefined();
	});

	it("advertises logout endpoints in discovery", () => {
		const doc = ctx.provider.getDiscoveryDocument();
		expect(doc.end_session_endpoint).toBe(`${ISSUER}/logout`);
		expect(doc.backchannel_logout_supported).toBe(true);
		expect(doc.backchannel_logout_session_supported).toBe(true);
	});

	it("rejects logout fields without config.logout", async () => {
		const pair = await jose.generateKeyPair("RS256", { extractable: true });
		const plain = createOidcProviderModule(
			{ issuer: ISSUER, signingKey: pair.privateKey as CryptoKey },
			ctx.db,
			async (userId) => ({ sub: userId }),
		);
		const res = await plain.registerClient({
			clientName: "x",
			redirectUris: ["https://rp.example.com/cb"],
			backchannelLogoutUri: "https://rp.example.com/bc",
		});
		expect(res.success).toBe(false);
	});

	it("puts a stable sid in the ID token", async () => {
		const first = await login(ctx.provider, ctx.sessions);
		const claims = jose.decodeJwt(first.tokens.idToken);
		expect(typeof claims.sid).toBe("string");
		const refreshed = await ctx.provider.exchangeToken({
			grantType: "refresh_token",
			refreshToken: first.tokens.refreshToken,
			clientId: first.client.clientId,
			...(first.client.clientSecret && { clientSecret: first.client.clientSecret }),
		});
		if (!refreshed.success) throw new Error("refresh failed");
		expect(jose.decodeJwt(refreshed.data.idToken).sid).toBe(claims.sid);
	});

	it("end session validates the hint, redirects to an allowed URI and fans out", async () => {
		const { client, tokens, sessionId } = await login(ctx.provider, ctx.sessions);
		const url = new URL(`${ISSUER}/logout`);
		url.searchParams.set("id_token_hint", tokens.idToken);
		url.searchParams.set("post_logout_redirect_uri", "https://rp.example.com/bye");
		url.searchParams.set("state", "xyz");

		const res = await ctx.provider.logout?.handleEndSession(new Request(url));
		expect(res?.status).toBe(302);
		expect(res?.headers.get("location")).toBe("https://rp.example.com/bye?state=xyz");

		expect(ctx.deliveries).toHaveLength(1);
		const delivery = ctx.deliveries[0];
		expect(delivery?.url).toBe("https://rp.example.com/backchannel");
		const payload = jose.decodeJwt(delivery?.token ?? "");
		expect(payload.aud).toBe(client.clientId);
		expect(payload.sub).toBe("user-1");
		expect(payload.sid).toBe(jose.decodeJwt(tokens.idToken).sid);

		// The provider session is gone.
		expect((await ctx.sessions.list("user-1")).find((s) => s.id === sessionId)).toBeUndefined();
	});

	it("rejects an unregistered post_logout_redirect_uri and a forged hint", async () => {
		const { tokens } = await login(ctx.provider, ctx.sessions);
		const bad = new URL(`${ISSUER}/logout`);
		bad.searchParams.set("id_token_hint", tokens.idToken);
		bad.searchParams.set("post_logout_redirect_uri", "https://evil.example.com/");
		expect((await ctx.provider.logout?.handleEndSession(new Request(bad)))?.status).toBe(400);

		const other = await jose.generateKeyPair("RS256");
		const forged = await new jose.SignJWT({ sid: "x" })
			.setProtectedHeader({ alg: "RS256" })
			.setIssuer(ISSUER)
			.setSubject("user-1")
			.setAudience("c")
			.sign(other.privateKey);
		const forgedUrl = new URL(`${ISSUER}/logout`);
		forgedUrl.searchParams.set("id_token_hint", forged);
		expect((await ctx.provider.logout?.handleEndSession(new Request(forgedUrl)))?.status).toBe(400);
		expect(ctx.deliveries).toHaveLength(0);
	});

	it("falls back to the default redirect without a redirect uri", async () => {
		const { tokens } = await login(ctx.provider, ctx.sessions);
		const url = new URL(`${ISSUER}/logout`);
		url.searchParams.set("id_token_hint", tokens.idToken);
		const res = await ctx.provider.logout?.handleEndSession(new Request(url));
		expect(res?.status).toBe(302);
		expect(res?.headers.get("location")).toBe("https://auth.test.com/signed-out");
	});

	it("fans out when a session is revoked outside the endpoint", async () => {
		const { sessionId } = await login(ctx.provider, ctx.sessions);
		await ctx.sessions.revoke(sessionId);
		expect(ctx.deliveries).toHaveLength(1);
	});

	it("does not send twice for one logout", async () => {
		const { tokens } = await login(ctx.provider, ctx.sessions);
		const url = new URL(`${ISSUER}/logout`);
		url.searchParams.set("id_token_hint", tokens.idToken);
		await ctx.provider.logout?.handleEndSession(new Request(url));
		await ctx.provider.logout?.handleEndSession(new Request(url));
		expect(ctx.deliveries).toHaveLength(1);
	});

	it("cleans up logout config when a client is deleted", async () => {
		const { client } = await login(ctx.provider, ctx.sessions);
		await ctx.provider.deleteClient(client.clientId);
		expect(await ctx.provider.logout?.getClientLogoutConfig(client.clientId)).toBeNull();
	});
});

describe("back-channel fan-out failures", () => {
	it("does not block local logout when delivery fails", async () => {
		const ctx = await setup({ failDelivery: true });
		const { tokens, sessionId } = await login(ctx.provider, ctx.sessions);
		const url = new URL(`${ISSUER}/logout`);
		url.searchParams.set("id_token_hint", tokens.idToken);
		url.searchParams.set("post_logout_redirect_uri", "https://rp.example.com/bye");

		const res = await ctx.provider.logout?.handleEndSession(new Request(url));
		expect(res?.status).toBe(302);
		expect(ctx.deliveries).toHaveLength(1);
		expect((await ctx.sessions.list("user-1")).find((s) => s.id === sessionId)).toBeUndefined();
	});

	it("reports failures from fanOut without throwing", async () => {
		const ctx = await setup({ failDelivery: true });
		await login(ctx.provider, ctx.sessions);
		const result = await ctx.provider.logout?.fanOut({ userId: "user-1" });
		expect(result).toEqual({ attempted: 1, delivered: 0, failed: 1 });
	});
});

describe("RP back-channel receiver revokes sessions", () => {
	async function makeRp() {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const now = new Date();
		await db
			.insert(users)
			.values({ id: "u1", email: "u1@rp.test", createdAt: now, updatedAt: now });
		const sessions = createSessionManager({ secret: SECRET }, db);
		return { db, sessions };
	}

	async function logoutToken(
		key: CryptoKey,
		claims: { sub?: string; sid?: string },
	): Promise<string> {
		return new jose.SignJWT({
			events: { "http://schemas.openid.net/event/backchannel-logout": {} },
			...claims,
		})
			.setProtectedHeader({ alg: "RS256", typ: "logout+jwt" })
			.setIssuer(ISSUER)
			.setAudience("rp-client")
			.setIssuedAt()
			.setJti(crypto.randomUUID())
			.sign(key);
	}

	function post(token: string): Request {
		return new Request("https://rp.test/bc", {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ logout_token: token }).toString(),
		});
	}

	it("revokes only the matching sid for a user by default", async () => {
		const { sessions } = await makeRp();
		const a = await sessions.create("u1", { sid: "sid-a" });
		const b = await sessions.create("u1", { sid: "sid-b" });
		const pair = await jose.generateKeyPair("RS256");
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISSUER,
			clientId: "rp-client",
			verificationKey: pair.publicKey,
			sessionManager: sessions,
		});
		const res = await receiver.handleRequest(
			post(await logoutToken(pair.privateKey as CryptoKey, { sub: "u1", sid: "sid-a" })),
		);
		expect(res.status).toBe(200);
		expect(await sessions.validate(a.token)).toBeNull();
		expect(await sessions.validate(b.token)).not.toBeNull();
	});

	it("revokes every session for a sub-only token", async () => {
		const { sessions } = await makeRp();
		const a = await sessions.create("u1");
		const b = await sessions.create("u1");
		const pair = await jose.generateKeyPair("RS256");
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISSUER,
			clientId: "rp-client",
			verificationKey: pair.publicKey,
			sessionManager: sessions,
		});
		const res = await receiver.handleRequest(
			post(await logoutToken(pair.privateKey as CryptoKey, { sub: "u1" })),
		);
		expect(res.status).toBe(200);
		expect(await sessions.validate(a.token)).toBeNull();
		expect(await sessions.validate(b.token)).toBeNull();
	});

	it("uses an injected revoker and still calls onLogout", async () => {
		const pair = await jose.generateKeyPair("RS256");
		const calls: string[] = [];
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISSUER,
			clientId: "rp-client",
			verificationKey: pair.publicKey,
			revokeSessions: async (claims) => {
				calls.push(`revoke:${claims.sub}`);
				return { revoked: 0 };
			},
			onLogout: async (claims) => {
				calls.push(`after:${claims.sid}`);
			},
		});
		const res = await receiver.handleRequest(
			post(await logoutToken(pair.privateKey as CryptoKey, { sub: "u9", sid: "s" })),
		);
		expect(res.status).toBe(200);
		expect(calls).toEqual(["revoke:u9", "after:s"]);
	});

	it("answers 400 for a sid-only token without a sid finder", async () => {
		const { sessions } = await makeRp();
		const pair = await jose.generateKeyPair("RS256");
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISSUER,
			clientId: "rp-client",
			verificationKey: pair.publicKey,
			sessionManager: sessions,
		});
		const res = await receiver.handleRequest(
			post(await logoutToken(pair.privateKey as CryptoKey, { sid: "only" })),
		);
		expect(res.status).toBe(400);
	});

	it("sid-only works with findSessionsBySid", async () => {
		const { sessions } = await makeRp();
		const s = await sessions.create("u1", { sid: "only" });
		const pair = await jose.generateKeyPair("RS256");
		const revoke = createSessionRevoker({
			sessionManager: sessions,
			findSessionsBySid: async (sid) =>
				(await sessions.list("u1")).filter((x) => x.metadata?.sid === sid),
		});
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISSUER,
			clientId: "rp-client",
			verificationKey: pair.publicKey,
			revokeSessions: revoke,
		});
		const res = await receiver.handleRequest(
			post(await logoutToken(pair.privateKey as CryptoKey, { sid: "only" })),
		);
		expect(res.status).toBe(200);
		expect(await sessions.validate(s.token)).toBeNull();
	});

	it("answers 400 when nothing is configured to log out", async () => {
		const pair = await jose.generateKeyPair("RS256");
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISSUER,
			clientId: "rp-client",
			verificationKey: pair.publicKey,
		});
		const res = await receiver.handleRequest(
			post(await logoutToken(pair.privateKey as CryptoKey, { sub: "u1" })),
		);
		expect(res.status).toBe(400);
	});
});
