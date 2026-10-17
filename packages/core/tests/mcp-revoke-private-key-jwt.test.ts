/** RFC 7009 revocation with private_key_jwt client authentication, plus the unchanged client_secret flow. */
import { describe, expect, it } from "vitest";
import {
	addClient,
	BASE_URL,
	basicAuth,
	CLIENT_ASSERTION_TYPE,
	clientAssertion,
	makeHarness,
	newKeys,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const REVOKE_URL = `${BASE_URL}/mcp/revoke`;
const GRANT = "client_credentials";

function revokeRequest(body: Record<string, string>, headers: Record<string, string> = {}) {
	return new Request(REVOKE_URL, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
		body: new URLSearchParams(body).toString(),
	});
}

async function setup() {
	const h = makeHarness({
		clientCredentials: {
			enabled: true,
			resolvePrincipal: async (client) => ({
				subject: `svc:${client.clientId}`,
				agentId: `agent:${client.clientId}`,
				agentType: "autonomous",
			}),
		},
	});
	const keys = await newKeys();
	const other = await newKeys("ES256", "k2");
	await addClient(h, {
		clientId: "pk",
		grantTypes: [GRANT],
		scope: "mcp:read",
		authMethod: "private_key_jwt",
		jwks: { keys: [keys.jwk] },
	});
	await addClient(h, {
		clientId: "pk-other",
		grantTypes: [GRANT],
		scope: "mcp:read",
		authMethod: "private_key_jwt",
		jwks: { keys: [other.jwk] },
	});
	await addClient(h, {
		clientId: "secret-client",
		secret: "s3cret-value",
		grantTypes: [GRANT],
		scope: "mcp:read",
	});
	return { h, keys, other };
}

async function issue(h: Awaited<ReturnType<typeof setup>>["h"], body: Record<string, string>) {
	const res = await h.mcp.token(
		tokenRequest({ grant_type: GRANT, scope: "mcp:read", resource: RESOURCE, ...body }),
	);
	if (!res.success) throw new Error(res.error.message);
	return res.data.access_token;
}

describe("/mcp/revoke with private_key_jwt", () => {
	it("revokes an access token with a signed assertion", async () => {
		const { h, keys } = await setup();
		const token = await issue(h, {
			client_assertion_type: CLIENT_ASSERTION_TYPE,
			client_assertion: await clientAssertion(keys, "pk"),
		});
		expect((await h.mcp.validateToken(token)).success).toBe(true);

		const res = await h.mcp.revoke(
			revokeRequest({
				token,
				token_type_hint: "access_token",
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: await clientAssertion(keys, "pk", { aud: REVOKE_URL }),
			}),
		);
		expect(res.success).toBe(true);
		expect((await h.mcp.validateToken(token)).success).toBe(false);
	});

	it("rejects a replayed assertion", async () => {
		const { h, keys } = await setup();
		const assertion = await clientAssertion(keys, "pk", { aud: REVOKE_URL, jti: "once" });
		const body = {
			token: "anything",
			client_assertion_type: CLIENT_ASSERTION_TYPE,
			client_assertion: assertion,
		};
		expect((await h.mcp.revoke(revokeRequest(body))).success).toBe(true);
		const again = await h.mcp.revoke(revokeRequest(body));
		expect(again.success).toBe(false);
		if (!again.success) expect(again.error.code).toBe("INVALID_CLIENT");
	});

	it("rejects an assertion addressed to the token endpoint", async () => {
		const { h, keys } = await setup();
		const res = await h.mcp.revoke(
			revokeRequest({
				token: "anything",
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: await clientAssertion(keys, "pk"),
			}),
		);
		expect(res.success).toBe(false);
	});

	it("rejects an assertion signed with another client's key", async () => {
		const { h, other } = await setup();
		const res = await h.mcp.revoke(
			revokeRequest({
				token: "anything",
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: await clientAssertion(other, "pk", { aud: REVOKE_URL }),
			}),
		);
		expect(res.success).toBe(false);
	});

	it("does not revoke another client's token", async () => {
		const { h, keys, other } = await setup();
		const token = await issue(h, {
			client_assertion_type: CLIENT_ASSERTION_TYPE,
			client_assertion: await clientAssertion(other, "pk-other"),
		});
		const res = await h.mcp.revoke(
			revokeRequest({
				token,
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: await clientAssertion(keys, "pk", { aud: REVOKE_URL }),
			}),
		);
		expect(res.success).toBe(true);
		expect((await h.mcp.validateToken(token)).success).toBe(true);
	});

	it("refuses an assertion combined with a client secret", async () => {
		const { h, keys } = await setup();
		const res = await h.mcp.revoke(
			revokeRequest(
				{
					token: "anything",
					client_assertion_type: CLIENT_ASSERTION_TYPE,
					client_assertion: await clientAssertion(keys, "pk", { aud: REVOKE_URL }),
				},
				basicAuth("secret-client", "s3cret-value"),
			),
		);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_REQUEST");
	});

	it("refuses a secret for a private_key_jwt client", async () => {
		const { h } = await setup();
		const res = await h.mcp.revoke(
			revokeRequest({ token: "x", client_id: "pk", client_secret: "guess" }),
		);
		expect(res.success).toBe(false);
	});

	it("keeps client_secret_basic revocation working", async () => {
		const { h } = await setup();
		const res = await h.mcp.token(
			tokenRequest(
				{ grant_type: GRANT, scope: "mcp:read", resource: RESOURCE },
				basicAuth("secret-client", "s3cret-value"),
			),
		);
		expect(res.success).toBe(true);
		if (!res.success) return;
		const revoked = await h.mcp.revoke(
			revokeRequest(
				{ token: res.data.access_token, token_type_hint: "access_token" },
				basicAuth("secret-client", "s3cret-value"),
			),
		);
		expect(revoked.success).toBe(true);
		expect((await h.mcp.validateToken(res.data.access_token)).success).toBe(false);
	});
});
