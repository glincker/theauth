/** RFC 8693 token exchange: subject and actor validation, scope narrowing, audience policy, nested `act`, chain depth, revocation and DPoP. */
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createMcpModule } from "../src/mcp/server.js";
import type { McpConfig, McpTokenResponse } from "../src/mcp/types.js";
import type { Harness } from "./mcp-test-harness.js";
import {
	addClient,
	basicAuth,
	codeFlow,
	decodePayload,
	dpopProof,
	ISSUER,
	makeHarness,
	newKeys,
	RESOURCE,
	RESOURCE_B,
	tokenRequest,
} from "./mcp-test-harness.js";

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";

async function setup(config: Partial<McpConfig> = {}) {
	const h = makeHarness({ tokenExchange: { enabled: true }, ...config });
	await addClient(h, { clientId: "app", grantTypes: ["authorization_code", "refresh_token"] });
	await addClient(h, { clientId: "xch", secret: "xs", grantTypes: [TE] });
	return h;
}

function exchange(
	h: Harness,
	body: Record<string, string>,
	headers: Record<string, string> = basicAuth("xch", "xs"),
) {
	return h.mcp.token(tokenRequest({ grant_type: TE, subject_token_type: AT, ...body }, headers));
}

async function ok(r: ReturnType<typeof exchange>): Promise<McpTokenResponse> {
	const res = await r;
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data;
}

describe("token exchange", () => {
	it("is off by default and needs a jti denylist when enabled", async () => {
		const h = makeHarness();
		await addClient(h, { clientId: "xch", secret: "xs", grantTypes: [TE] });
		const res = await exchange(h, { subject_token: "x" });
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("UNSUPPORTED_GRANT_TYPE");
		expect(h.mcp.getMetadata().grant_types_supported).not.toContain(TE);
		expect(() =>
			createMcpModule({
				config: {
					enabled: true,
					issuer: ISSUER,
					baseUrl: "https://auth.theauth.test/api/auth",
					signingSecret: "test-signing-secret-at-least-32-chars-long!!",
					tokenExchange: { enabled: true },
				},
				storeClient: async () => {},
				findClient: async () => null,
				storeAuthorizationCode: async () => {},
				consumeAuthorizationCode: async () => null,
				storeToken: async () => {},
				findTokenByRefreshToken: async () => null,
				revokeToken: async () => {},
				resolveUserId: async () => null,
			}),
		).toThrow(/jtiDenylist/);
	});

	it("narrows scope, emits act and never outlives the subject token", async () => {
		const h = await setup();
		const subject = await codeFlow(h, "app", { scope: "mcp:read mcp:write" });
		const out = await ok(exchange(h, { subject_token: subject.access_token, scope: "mcp:read" }));
		expect(out.scope).toBe("mcp:read");
		expect(out.refresh_token).toBeUndefined();
		expect(out.issued_token_type).toBe(AT);
		expect(out.expires_in).toBeLessThanOrEqual(subject.expires_in);
		const claims = decodePayload(out.access_token);
		expect(claims.sub).toBe(decodePayload(subject.access_token).sub);
		expect(claims.client_id).toBe("xch");
		expect(claims.act).toEqual({ sub: "xch", client_id: "xch" });
		expect(claims.exp as number).toBeLessThanOrEqual(
			decodePayload(subject.access_token).exp as number,
		);
		const session = await h.mcp.validateToken(out.access_token, ["mcp:read"]);
		expect(session.success).toBe(true);
		if (session.success)
			expect(session.data.delegationChain).toEqual([{ sub: "xch", clientId: "xch" }]);
		expect(h.mcp.getMetadata().grant_types_supported).toContain(TE);
	});

	it("keeps the subject scope when none is requested and refuses widening", async () => {
		const h = await setup();
		const subject = await codeFlow(h, "app", { scope: "mcp:read" });
		const same = await ok(exchange(h, { subject_token: subject.access_token }));
		expect(same.scope).toBe("mcp:read");
		const wide = await exchange(h, {
			subject_token: subject.access_token,
			scope: "mcp:read mcp:write",
		});
		expect(wide.success).toBe(false);
		if (!wide.success) expect(wide.error.code).toBe("INVALID_SCOPE");
	});

	it("changes audience only to a configured resource", async () => {
		const h = await setup({ allowedResources: [RESOURCE, RESOURCE_B] });
		const subject = await codeFlow(h, "app");
		const moved = await ok(
			exchange(h, { subject_token: subject.access_token, resource: RESOURCE_B }),
		);
		expect(decodePayload(moved.access_token).aud).toBe(RESOURCE_B);
		const via = await ok(
			exchange(h, { subject_token: subject.access_token, audience: RESOURCE_B }),
		);
		expect(decodePayload(via.access_token).aud).toBe(RESOURCE_B);
		const evil = await exchange(h, {
			subject_token: subject.access_token,
			resource: "https://evil.test",
		});
		expect(evil.success).toBe(false);
		if (!evil.success) expect(evil.error.code).toBe("INVALID_TARGET");
	});

	it("uses the actor token identity and nests earlier hops", async () => {
		const h = await setup();
		const subject = await codeFlow(h, "app");
		const actor = await codeFlow(h, "app");
		const first = await ok(
			exchange(h, {
				subject_token: subject.access_token,
				actor_token: actor.access_token,
				actor_token_type: AT,
			}),
		);
		const act = decodePayload(first.access_token).act as { sub: string; client_id: string };
		expect(act).toEqual({ sub: decodePayload(actor.access_token).sub, client_id: "app" });
		const second = await ok(exchange(h, { subject_token: first.access_token }));
		expect(decodePayload(second.access_token).act).toEqual({
			sub: "xch",
			client_id: "xch",
			act,
		});
	});

	it("rejects an actor token without a token type", async () => {
		const h = await setup();
		const subject = await codeFlow(h, "app");
		const actor = await codeFlow(h, "app");
		const res = await exchange(h, {
			subject_token: subject.access_token,
			actor_token: actor.access_token,
		});
		expect(res.success).toBe(false);
	});

	it("caps the delegation chain at 3 hops", async () => {
		const h = await setup();
		let token = (await codeFlow(h, "app")).access_token;
		for (let i = 0; i < 3; i += 1) {
			token = (await ok(exchange(h, { subject_token: token }))).access_token;
		}
		const fourth = await exchange(h, { subject_token: token });
		expect(fourth.success).toBe(false);
		if (!fourth.success) expect(fourth.error.code).toBe("INVALID_REQUEST");
	});

	it("honors maxChainDepth", async () => {
		const h = await setup({ tokenExchange: { enabled: true, maxChainDepth: 1 } });
		const first = await ok(exchange(h, { subject_token: (await codeFlow(h, "app")).access_token }));
		const second = await exchange(h, { subject_token: first.access_token });
		expect(second.success).toBe(false);
	});

	it("rejects revoked subject tokens", async () => {
		const h = await setup();
		const subject = await codeFlow(h, "app");
		const revoked = await h.mcp.revoke(
			tokenRequest({
				token: subject.access_token,
				client_id: "app",
				token_type_hint: "access_token",
			}),
		);
		expect(revoked.success).toBe(true);
		const res = await exchange(h, { subject_token: subject.access_token });
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_GRANT");
	});

	it("rejects foreign, malformed and wrong-typed tokens", async () => {
		const h = await setup();
		const forged = await new SignJWT({ sub: "u", client_id: "app", scope: "mcp:read", jti: "j" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuer(ISSUER)
			.setAudience(RESOURCE)
			.setExpirationTime("1h")
			.sign(new TextEncoder().encode("a-different-secret-that-is-long-enough!!"));
		for (const token of [forged, "not-a-jwt"]) {
			const res = await exchange(h, { subject_token: token });
			expect(res.success).toBe(false);
			if (!res.success) expect(res.error.code).toBe("INVALID_GRANT");
		}
		const subject = await codeFlow(h, "app");
		const badType = await h.mcp.token(
			tokenRequest(
				{
					grant_type: TE,
					subject_token: subject.access_token,
					subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
				},
				basicAuth("xch", "xs"),
			),
		);
		expect(badType.success).toBe(false);
	});

	it("requires the client to hold the grant and authenticate", async () => {
		const h = await setup();
		await addClient(h, { clientId: "plain", secret: "ps", grantTypes: ["authorization_code"] });
		const subject = await codeFlow(h, "app");
		const noGrant = await exchange(
			h,
			{ subject_token: subject.access_token },
			basicAuth("plain", "ps"),
		);
		expect(noGrant.success).toBe(false);
		if (!noGrant.success) expect(noGrant.error.code).toBe("UNAUTHORIZED_CLIENT");
		const badSecret = await exchange(
			h,
			{ subject_token: subject.access_token },
			basicAuth("xch", "no"),
		);
		expect(badSecret.success).toBe(false);
	});

	it("applies the authorize policy hook", async () => {
		const h = await setup({
			tokenExchange: { enabled: true, authorize: async (input) => input.client.clientId !== "xch" },
		});
		const subject = await codeFlow(h, "app");
		const res = await exchange(h, { subject_token: subject.access_token });
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("ACCESS_DENIED");
	});

	describe("with DPoP", () => {
		it("requires a proof from the bound key and keeps the binding", async () => {
			const h = await setup({ dpop: {} });
			const keys = await newKeys();
			const subject = await codeFlow(h, "app", { dpop: keys });
			expect(subject.token_type).toBe("DPoP");

			const none = await exchange(h, { subject_token: subject.access_token });
			expect(none.success).toBe(false);

			const other = await newKeys();
			const wrong = await exchange(
				h,
				{ subject_token: subject.access_token },
				{
					...basicAuth("xch", "xs"),
					DPoP: await dpopProof(other),
				},
			);
			expect(wrong.success).toBe(false);

			const right = await ok(
				exchange(
					h,
					{ subject_token: subject.access_token },
					{
						...basicAuth("xch", "xs"),
						DPoP: await dpopProof(keys),
					},
				),
			);
			expect(right.token_type).toBe("DPoP");
			expect(decodePayload(right.access_token).cnf).toEqual(
				decodePayload(subject.access_token).cnf,
			);
		});

		it("lets a proof bind an unbound subject token's exchange result", async () => {
			const h = await setup({ dpop: {} });
			const subject = await codeFlow(h, "app");
			const keys = await newKeys();
			const out = await ok(
				exchange(
					h,
					{ subject_token: subject.access_token },
					{
						...basicAuth("xch", "xs"),
						DPoP: await dpopProof(keys),
					},
				),
			);
			expect(out.token_type).toBe("DPoP");
		});
	});
});
