/** client_credentials grant: opt in, confidential clients only, scope-limited, principal mapping, DPoP binding, and private_key_jwt client authentication. */
import { describe, expect, it } from "vitest";
import type { McpConfig } from "../src/mcp/types.js";
import type { Harness } from "./mcp-test-harness.js";
import {
	addClient,
	basicAuth,
	CLIENT_ASSERTION_TYPE,
	clientAssertion,
	decodePayload,
	dpopProof,
	makeHarness,
	newKeys,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const GRANT = "client_credentials";

function enabled(overrides: Partial<McpConfig> = {}): Harness {
	return makeHarness({
		clientCredentials: {
			enabled: true,
			resolvePrincipal: async (client) =>
				client.clientId === "svc-none"
					? null
					: {
							subject: `svc:${client.clientId}`,
							agentId: `agent:${client.clientId}`,
							agentType: "autonomous",
							trustTier: "standard",
						},
		},
		...overrides,
	});
}

async function request(h: Harness, body: Record<string, string>, headers = {}) {
	return h.mcp.token(tokenRequest({ grant_type: GRANT, resource: RESOURCE, ...body }, headers));
}

describe("client_credentials", () => {
	it("is off by default", async () => {
		const h = makeHarness();
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read",
		});
		const res = await request(h, {}, basicAuth("svc", "s3cret"));
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("UNSUPPORTED_GRANT_TYPE");
		expect(h.mcp.getMetadata().grant_types_supported).not.toContain(GRANT);
	});

	it("issues a scope-limited token for the mapped principal, with no refresh token", async () => {
		const h = enabled();
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read mcp:write offline_access",
		});
		const res = await request(h, { scope: "mcp:read" }, basicAuth("svc", "s3cret"));
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data.refresh_token).toBeUndefined();
		expect(res.data.scope).toBe("mcp:read");
		expect(res.data.token_type).toBe("Bearer");
		const payload = decodePayload(res.data.access_token);
		expect(payload.sub).toBe("svc:svc");
		expect(payload.client_id).toBe("svc");
		expect(payload.aud).toBe(RESOURCE);
		expect(payload.agent_id).toBe("agent:svc");
		expect(payload.agent_type).toBe("autonomous");
		const session = await h.mcp.validateToken(res.data.access_token, ["mcp:read"]);
		expect(session.success).toBe(true);
		if (session.success) expect(session.data.agent?.id).toBe("agent:svc");
		expect(h.mcp.getMetadata().grant_types_supported).toContain(GRANT);
	});

	it("defaults to the registered scope minus offline_access", async () => {
		const h = enabled();
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read offline_access",
		});
		const res = await request(h, {}, basicAuth("svc", "s3cret"));
		expect(res.success && res.data.scope).toBe("mcp:read");
	});

	it("refuses scopes beyond the registered ones", async () => {
		const h = enabled();
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read",
		});
		const res = await request(h, { scope: "mcp:read mcp:admin" }, basicAuth("svc", "s3cret"));
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_SCOPE");
		const offline = await request(h, { scope: "offline_access" }, basicAuth("svc", "s3cret"));
		expect(offline.success).toBe(false);
	});

	it("accepts client_secret_post and rejects a wrong secret", async () => {
		const h = enabled();
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read",
		});
		const post = await request(h, { client_id: "svc", client_secret: "s3cret" });
		expect(post.success).toBe(true);
		const bad = await request(h, { client_id: "svc", client_secret: "nope" });
		expect(bad.success).toBe(false);
		if (!bad.success) expect(bad.error.code).toBe("INVALID_CLIENT");
	});

	it("refuses public clients, clients without the grant and unmapped clients", async () => {
		const h = enabled();
		await addClient(h, { clientId: "pub", grantTypes: [GRANT], scope: "mcp:read" });
		await addClient(h, { clientId: "nogrant", secret: "s", scope: "mcp:read" });
		await addClient(h, {
			clientId: "svc-none",
			secret: "s",
			grantTypes: [GRANT],
			scope: "mcp:read",
		});
		const pub = await request(h, { client_id: "pub" });
		expect(pub.success).toBe(false);
		const noGrant = await request(h, {}, basicAuth("nogrant", "s"));
		expect(noGrant.success).toBe(false);
		if (!noGrant.success) expect(noGrant.error.code).toBe("UNAUTHORIZED_CLIENT");
		const unmapped = await request(h, {}, basicAuth("svc-none", "s"));
		expect(unmapped.success).toBe(false);
		if (!unmapped.success) expect(unmapped.error.code).toBe("UNAUTHORIZED_CLIENT");
	});

	it("requires a resource unless optionalResource is on", async () => {
		const h = enabled();
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read",
		});
		const res = await h.mcp.token(tokenRequest({ grant_type: GRANT }, basicAuth("svc", "s3cret")));
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_TARGET");
	});

	it("binds the token to a DPoP key when a proof is sent", async () => {
		const h = enabled({ dpop: {} });
		await addClient(h, {
			clientId: "svc",
			secret: "s3cret",
			grantTypes: [GRANT],
			scope: "mcp:read",
		});
		const keys = await newKeys();
		const res = await request(
			h,
			{},
			{ ...basicAuth("svc", "s3cret"), DPoP: await dpopProof(keys) },
		);
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data.token_type).toBe("DPoP");
		const cnf = decodePayload(res.data.access_token).cnf as { jkt: string };
		expect(cnf.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
		// A bound token never validates as a bare bearer token.
		const bare = await h.mcp.validateToken(res.data.access_token);
		expect(bare.success).toBe(false);
	});

	it("registers client_credentials clients only when the grant is enabled", async () => {
		const off = makeHarness();
		const refused = await off.mcp.registerClient({
			redirect_uris: [],
			grant_types: [GRANT],
			scope: "mcp:read",
		});
		expect(refused.success).toBe(false);
		const on = enabled();
		const ok = await on.mcp.registerClient({
			redirect_uris: [],
			grant_types: [GRANT],
			scope: "mcp:read",
		});
		expect(ok.success).toBe(true);
		if (!ok.success) return;
		const res = await request(on, {}, basicAuth(ok.data.client_id, ok.data.client_secret ?? ""));
		expect(res.success).toBe(true);
		const pub = await on.mcp.registerClient({
			redirect_uris: [],
			grant_types: [GRANT],
			token_endpoint_auth_method: "none",
		});
		expect(pub.success).toBe(false);
	});
});

describe("private_key_jwt client authentication", () => {
	async function setup() {
		const h = enabled();
		const keys = await newKeys();
		await addClient(h, {
			clientId: "pk",
			grantTypes: [GRANT],
			scope: "mcp:read",
			authMethod: "private_key_jwt",
			jwks: { keys: [keys.jwk] },
		});
		return { h, keys };
	}

	function assertionBody(assertion: string, extra: Record<string, string> = {}) {
		return {
			client_assertion_type: CLIENT_ASSERTION_TYPE,
			client_assertion: assertion,
			...extra,
		};
	}

	it("authenticates with a signed assertion and derives client_id from it", async () => {
		const { h, keys } = await setup();
		const res = await request(h, assertionBody(await clientAssertion(keys, "pk")));
		expect(res.success).toBe(true);
		if (res.success) expect(decodePayload(res.data.access_token).client_id).toBe("pk");
	});

	it("rejects a replayed assertion", async () => {
		const { h, keys } = await setup();
		const assertion = await clientAssertion(keys, "pk", { jti: "once" });
		expect((await request(h, assertionBody(assertion))).success).toBe(true);
		const again = await request(h, assertionBody(assertion));
		expect(again.success).toBe(false);
		if (!again.success) expect(again.error.code).toBe("INVALID_CLIENT");
	});

	it("rejects wrong audience, wrong key, long lifetime and mismatched client_id", async () => {
		const { h, keys } = await setup();
		const other = await newKeys();
		const cases: string[] = [
			await clientAssertion(keys, "pk", { aud: "https://evil.test/token" }),
			await clientAssertion(other, "pk"),
			await clientAssertion(keys, "pk", { expiresIn: 3600 }),
			await clientAssertion(keys, "pk", { sub: "someone-else" }),
		];
		for (const assertion of cases) {
			const res = await request(h, assertionBody(assertion));
			expect(res.success).toBe(false);
			if (!res.success) expect(res.error.code).toBe("INVALID_CLIENT");
		}
		const mismatch = await request(
			h,
			assertionBody(await clientAssertion(keys, "pk"), { client_id: "another" }),
		);
		expect(mismatch.success).toBe(false);
	});

	it("does not mix an assertion with a secret, and secrets never work for these clients", async () => {
		const { h, keys } = await setup();
		const mixed = await h.mcp.token(
			tokenRequest(
				{
					grant_type: GRANT,
					resource: RESOURCE,
					...assertionBody(await clientAssertion(keys, "pk")),
				},
				basicAuth("pk", "whatever"),
			),
		);
		expect(mixed.success).toBe(false);
		const secretOnly = await request(h, { client_id: "pk", client_secret: "x" });
		expect(secretOnly.success).toBe(false);
	});

	it("rejects an assertion from a client registered for a secret", async () => {
		const h = enabled();
		const keys = await newKeys();
		await addClient(h, { clientId: "sec", secret: "s", grantTypes: [GRANT], scope: "mcp:read" });
		const res = await request(h, assertionBody(await clientAssertion(keys, "sec")));
		expect(res.success).toBe(false);
	});

	it("registers private_key_jwt clients with jwks and advertises the method", async () => {
		const h = enabled();
		const keys = await newKeys();
		const ok = await h.mcp.registerClient({
			redirect_uris: [],
			grant_types: [GRANT],
			token_endpoint_auth_method: "private_key_jwt",
			jwks: { keys: [keys.jwk] },
			scope: "mcp:read",
		});
		expect(ok.success).toBe(true);
		if (!ok.success) return;
		expect(ok.data.client_secret).toBeUndefined();
		const res = await request(h, assertionBody(await clientAssertion(keys, ok.data.client_id)));
		expect(res.success).toBe(true);
		const none = await h.mcp.registerClient({
			redirect_uris: [],
			grant_types: [GRANT],
			token_endpoint_auth_method: "private_key_jwt",
		});
		expect(none.success).toBe(false);
		expect(h.mcp.getMetadata().token_endpoint_auth_methods_supported).toContain("private_key_jwt");
	});
});
