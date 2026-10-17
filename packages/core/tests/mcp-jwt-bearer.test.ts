/** RFC 7523 jwt-bearer redemption of ID-JAG assertions from trusted issuers. */
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import type { McpConfig } from "../src/mcp/types.js";
import type { Harness, KeyMaterial } from "./mcp-test-harness.js";
import {
	addClient,
	basicAuth,
	decodePayload,
	dpopProof,
	ISSUER,
	makeHarness,
	newKeys,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const JB = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const IDP = "https://idp.corp.test";
const JWKS_URI = "https://idp.corp.test/.well-known/jwks.json";

interface JagInit {
	iss?: string;
	sub?: string;
	aud?: string;
	clientId?: string;
	typ?: string;
	alg?: string;
	iat?: number;
	exp?: number;
	jti?: string;
	scope?: string;
	resource?: string;
	omit?: string[];
}

async function jag(keys: KeyMaterial, init: JagInit = {}): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const claims: Record<string, unknown> = {
		iss: init.iss ?? IDP,
		sub: init.sub ?? "alice@corp.test",
		aud: init.aud ?? ISSUER,
		client_id: init.clientId ?? "agent",
		jti: init.jti ?? crypto.randomUUID(),
		iat: init.iat ?? now,
		exp: init.exp ?? now + 60,
		scope: init.scope ?? "mcp:read mcp:write",
		...(init.resource ? { resource: init.resource } : {}),
	};
	for (const k of init.omit ?? []) Reflect.deleteProperty(claims, k);
	return new SignJWT(claims)
		.setProtectedHeader({
			alg: init.alg ?? "ES256",
			typ: init.typ ?? "oauth-id-jag+jwt",
			kid: keys.jwk.kid ?? "k1",
		})
		.sign(keys.privateKey);
}

async function setup(config: Partial<McpConfig> = {}, idpKeys?: KeyMaterial) {
	const keys = idpKeys ?? (await newKeys());
	const mapSubject = vi.fn(async (input: { subject: string }) => `user:${input.subject}`);
	const h = makeHarness({
		jwtBearer: {
			enabled: true,
			trustedIssuers: [{ issuer: IDP, jwks: { keys: [keys.jwk] } }],
			mapSubject,
		},
		...config,
	});
	await addClient(h, { clientId: "agent", secret: "as", grantTypes: [JB] });
	return { h, keys, mapSubject };
}

function redeem(h: Harness, body: Record<string, string>, headers = basicAuth("agent", "as")) {
	return h.mcp.token(tokenRequest({ grant_type: JB, resource: RESOURCE, ...body }, headers));
}

async function fails(h: Harness, assertion: string, code = "INVALID_GRANT", extra = {}) {
	const res = await redeem(h, { assertion, ...extra });
	expect(res.success).toBe(false);
	if (!res.success) expect(res.error.code).toBe(code);
}

describe("jwt-bearer / ID-JAG", () => {
	it("is off by default", async () => {
		const h = makeHarness();
		await addClient(h, { clientId: "agent", secret: "as", grantTypes: [JB] });
		const res = await redeem(h, { assertion: "x" });
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("UNSUPPORTED_GRANT_TYPE");
		expect(h.mcp.getMetadata().grant_types_supported).not.toContain(JB);
	});

	it("redeems an assertion for a mapped user, scoped by the assertion", async () => {
		const { h, keys, mapSubject } = await setup();
		const res = await redeem(h, {
			assertion: await jag(keys, { scope: "mcp:read" }),
		});
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data.scope).toBe("mcp:read");
		expect(res.data.refresh_token).toBeUndefined();
		const claims = decodePayload(res.data.access_token);
		expect(claims.sub).toBe("user:alice@corp.test");
		expect(claims.client_id).toBe("agent");
		expect(claims.aud).toBe(RESOURCE);
		expect(mapSubject).toHaveBeenCalledWith(
			expect.objectContaining({ issuer: IDP, subject: "alice@corp.test", clientId: "agent" }),
		);
		expect(h.mcp.getMetadata().grant_types_supported).toContain(JB);
	});

	it("narrows to the requested scope and refuses widening", async () => {
		const { h, keys } = await setup();
		const narrowed = await redeem(h, {
			assertion: await jag(keys, { scope: "mcp:read mcp:write" }),
			scope: "mcp:write",
		});
		expect(narrowed.success && narrowed.data.scope).toBe("mcp:write");
		await fails(h, await jag(keys, { scope: "mcp:read" }), "INVALID_SCOPE", { scope: "mcp:admin" });
	});

	it("grants only openid when the assertion has no scope", async () => {
		const { h, keys } = await setup();
		const res = await redeem(h, { assertion: await jag(keys, { omit: ["scope"] }) });
		expect(res.success && res.data.scope).toBe("openid");
	});

	it("binds to a DPoP key when a proof is sent", async () => {
		const { h, keys } = await setup({ dpop: {} });
		const proofKeys = await newKeys();
		const res = await h.mcp.token(
			tokenRequest(
				{ grant_type: JB, resource: RESOURCE, assertion: await jag(keys) },
				{ ...basicAuth("agent", "as"), DPoP: await dpopProof(proofKeys) },
			),
		);
		expect(res.success && res.data.token_type).toBe("DPoP");
	});

	it("rejects bad typ, issuer, audience, client_id and signatures", async () => {
		const { h, keys } = await setup();
		const attacker = await newKeys();
		await fails(h, await jag(keys, { typ: "JWT" }));
		await fails(h, await jag(keys, { iss: "https://evil.test" }));
		await fails(h, await jag(keys, { aud: "https://other-as.test" }));
		await fails(h, await jag(keys, { clientId: "someone-else" }));
		await fails(h, await jag(attacker));
		await fails(h, await jag(keys, { omit: ["jti"] }));
		await fails(h, await jag(keys, { omit: ["client_id"] }));
		await fails(h, "garbage");
	});

	it("rejects expired, future and long-lived assertions", async () => {
		const { h, keys } = await setup();
		const now = Math.floor(Date.now() / 1000);
		await fails(h, await jag(keys, { iat: now - 600, exp: now - 300 }));
		await fails(h, await jag(keys, { iat: now + 3600, exp: now + 3660 }));
		await fails(h, await jag(keys, { iat: now, exp: now + 3600 }));
	});

	it("rejects disallowed algorithms", async () => {
		const { h, keys } = await setup({
			jwtBearer: {
				enabled: true,
				trustedIssuers: [{ issuer: IDP, jwks: { keys: [] } }],
				mapSubject: async () => "u",
				algs: ["EdDSA"],
			},
		});
		await fails(h, await jag(keys));
	});

	it("rejects a replayed jti", async () => {
		const { h, keys } = await setup();
		const assertion = await jag(keys, { jti: "one-shot" });
		expect((await redeem(h, { assertion })).success).toBe(true);
		await fails(h, assertion);
	});

	it("rejects when the subject cannot be mapped", async () => {
		const { h, keys, mapSubject } = await setup();
		mapSubject.mockResolvedValueOnce(null as unknown as string);
		await fails(h, await jag(keys));
	});

	it("requires client authentication and the grant on the client", async () => {
		const { h, keys } = await setup();
		await addClient(h, { clientId: "nogrant", secret: "ns", grantTypes: ["authorization_code"] });
		const assertion = await jag(keys, { clientId: "nogrant" });
		const noGrant = await redeem(h, { assertion }, basicAuth("nogrant", "ns"));
		expect(noGrant.success).toBe(false);
		if (!noGrant.success) expect(noGrant.error.code).toBe("UNAUTHORIZED_CLIENT");
		const bad = await redeem(h, { assertion: await jag(keys) }, basicAuth("agent", "wrong"));
		expect(bad.success).toBe(false);
		if (!bad.success) expect(bad.error.code).toBe("INVALID_CLIENT");
	});

	it("checks resource against the assertion", async () => {
		const { h, keys } = await setup({ allowedResources: [RESOURCE, "https://other.theauth.test"] });
		await fails(h, await jag(keys, { resource: "https://other.theauth.test" }), "INVALID_TARGET");
		const ok = await h.mcp.token(
			tokenRequest(
				{
					grant_type: JB,
					assertion: await jag(keys, { resource: "https://other.theauth.test" }),
				},
				basicAuth("agent", "as"),
			),
		);
		expect(ok.success && decodePayload(ok.data.access_token).aud).toBe(
			"https://other.theauth.test",
		);
	});

	describe("remote JWKS", () => {
		function jwksFetch(keysByCall: KeyMaterial[]) {
			let calls = 0;
			const fetchImpl = vi.fn(async () => {
				const keys = keysByCall[Math.min(calls, keysByCall.length - 1)];
				calls += 1;
				return new Response(JSON.stringify({ keys: keys ? [keys.jwk] : [] }), {
					status: 200,
					headers: { "content-type": "application/json" },
				});
			}) as unknown as typeof fetch;
			return fetchImpl;
		}

		it("fetches the issuer JWKS through the safe fetcher and caches it", async () => {
			const keys = await newKeys();
			const fetchImpl = jwksFetch([keys]);
			const { h } = await setup({
				jwtBearer: {
					enabled: true,
					trustedIssuers: [{ issuer: IDP, jwksUri: JWKS_URI }],
					mapSubject: async (i) => `user:${i.subject}`,
					resolver: async () => ["93.184.216.34"],
					fetchImpl,
				},
			});
			expect((await redeem(h, { assertion: await jag(keys) })).success).toBe(true);
			expect((await redeem(h, { assertion: await jag(keys) })).success).toBe(true);
			expect(fetchImpl).toHaveBeenCalledTimes(1);
		});

		it("refuses a JWKS URL that resolves to a private address", async () => {
			const keys = await newKeys();
			const fetchImpl = jwksFetch([keys]);
			const { h } = await setup({
				jwtBearer: {
					enabled: true,
					trustedIssuers: [{ issuer: IDP, jwksUri: JWKS_URI }],
					mapSubject: async (i) => `user:${i.subject}`,
					resolver: async () => ["10.0.0.5"],
					fetchImpl,
				},
			});
			await fails(h, await jag(keys));
			expect(fetchImpl).not.toHaveBeenCalled();
		});
	});
});
