/** requireScopes returns a typed denial (status, code, reason, attribution) and spec shaped challenges. */
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import type { McpDelegationLink } from "../src/mcp/types.js";
import {
	addClient,
	BASE_URL,
	basicAuth,
	codeFlow,
	ISSUER,
	makeHarness,
	RESOURCE,
	SECRET,
	tokenRequest,
} from "./mcp-test-harness.js";

const METADATA = `${BASE_URL}/.well-known/oauth-protected-resource`;
const key = new TextEncoder().encode(SECRET);

function req(token?: string): Request {
	return new Request("https://mcp.theauth.test/tools/call", {
		method: "POST",
		headers: token ? { authorization: `Bearer ${token}` } : {},
	});
}

async function sign(
	claims: Record<string, unknown>,
	options: { exp?: number; aud?: string; secret?: Uint8Array } = {},
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({
		sub: "user_1",
		client_id: "client-a",
		scope: "mcp:read",
		jti: "jti-1",
		...claims,
	})
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(options.aud ?? RESOURCE)
		.setIssuedAt(now - 120)
		.setExpirationTime(options.exp ?? now + 600)
		.sign(options.secret ?? key);
}

async function body(
	res: Response,
): Promise<{ error: { code: number; message: string; data: { code: string } } }> {
	return (await res.json()) as { error: { code: number; message: string; data: { code: string } } };
}

describe("requireScopes denials", () => {
	it("401 for a missing token: no error param, resource_metadata and scope present", async () => {
		const { mcp } = makeHarness();
		const res = await mcp.requireScopes(req(), ["mcp:read"]);
		expect(res.authorized).toBe(false);
		if (res.authorized) return;
		expect(res.status).toBe(401);
		expect(res.error.code).toBe("UNAUTHORIZED");
		expect(res.rejected).toBeUndefined();
		const header = res.response.headers.get("www-authenticate") ?? "";
		expect(header).toBe(`Bearer resource_metadata="${METADATA}", scope="mcp:read"`);
		const json = await body(res.response);
		expect(json.error.code).toBe(-32001);
		expect(json.error.data.code).toBe("UNAUTHORIZED");
	});

	it("401 invalid_token with an error_description, and no attribution, for an unverifiable token", async () => {
		const { mcp } = makeHarness();
		const forged = await sign(
			{},
			{ secret: new TextEncoder().encode("another-secret-another-secret-123456") },
		);
		for (const token of ["not-a-jwt", forged]) {
			const res = await mcp.requireScopes(req(token), ["mcp:read"]);
			expect(res.authorized).toBe(false);
			if (res.authorized) return;
			expect(res.status).toBe(401);
			expect(res.error.code).toBe("INVALID_TOKEN");
			expect(res.rejected).toBeUndefined();
			const header = res.response.headers.get("www-authenticate") ?? "";
			expect(header).toContain('error="invalid_token"');
			expect(header).toContain("error_description=");
			expect(header).toContain(`resource_metadata="${METADATA}"`);
			expect(header).toContain('scope="mcp:read"');
		}
	});

	it("names who an expired token belonged to, because its signature verified", async () => {
		const { mcp } = makeHarness();
		const token = await sign(
			{ agent_id: "ta_agent1" },
			{ exp: Math.floor(Date.now() / 1000) - 30 },
		);
		const res = await mcp.requireScopes(req(token), ["mcp:read"]);
		expect(res.authorized).toBe(false);
		if (res.authorized) return;
		expect(res.status).toBe(401);
		expect(res.error.code).toBe("TOKEN_EXPIRED");
		expect(res.rejected).toEqual({
			clientId: "client-a",
			subject: "user_1",
			tokenId: "jti-1",
			agentId: "ta_agent1",
		});
	});

	it("reports a token minted for another resource as INVALID_AUDIENCE with attribution", async () => {
		const { mcp } = makeHarness();
		const res = await mcp.requireScopes(
			req(await sign({}, { aud: "https://other.theauth.test" })),
			["mcp:read"],
		);
		expect(res.authorized).toBe(false);
		if (res.authorized) return;
		expect(res.error.code).toBe("INVALID_AUDIENCE");
		expect(res.rejected?.clientId).toBe("client-a");
	});

	it("reports a revoked token as INVALID_TOKEN with attribution", async () => {
		const { mcp } = makeHarness();
		const token = await sign({ jti: "revoked-1" });
		const ok = await mcp.requireScopes(req(token), ["mcp:read"]);
		expect(ok.authorized).toBe(true);
		const { createInMemoryJtiDenylist } = await import("../src/mcp/memory-stores.js");
		const denylist = createInMemoryJtiDenylist();
		await denylist.revoke("revoked-1", new Date(Date.now() + 60_000));
		const guarded = makeHarness({ jtiDenylist: denylist });
		const res = await guarded.mcp.requireScopes(req(token), ["mcp:read"]);
		expect(res.authorized).toBe(false);
		if (res.authorized) return;
		expect(res.error.code).toBe("INVALID_TOKEN");
		expect(res.error.message).toMatch(/revoked/);
		expect(res.rejected?.tokenId).toBe("revoked-1");
	});

	it("403 insufficient_scope carries scope and resource_metadata, and attributes the token", async () => {
		const { mcp } = makeHarness();
		const res = await mcp.requireScopes(req(await sign({ agent_id: "ta_a" })), ["mcp:write"]);
		expect(res.authorized).toBe(false);
		if (res.authorized) return;
		expect(res.status).toBe(403);
		expect(res.error.code).toBe("INSUFFICIENT_SCOPE");
		expect(res.error.message).toContain("mcp:write");
		expect(res.rejected).toMatchObject({ clientId: "client-a", agentId: "ta_a", tokenId: "jti-1" });
		const header = res.response.headers.get("www-authenticate") ?? "";
		expect(header).toContain('error="insufficient_scope"');
		expect(header).toContain('scope="mcp:write"');
		expect(header).toContain(`resource_metadata="${METADATA}"`);
		const json = (await res.response.json()) as { code: string; required_scopes: string[] };
		expect(json.code).toBe("INSUFFICIENT_SCOPE");
		expect(json.required_scopes).toEqual(["mcp:write"]);
	});

	it("reports a dead delegation chain as DELEGATION_REVOKED with attribution", async () => {
		const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
		const AT = "urn:ietf:params:oauth:token-type:access_token";
		const links = new Map<string, McpDelegationLink>([
			["user_1>xch", { status: "active", expiresAt: new Date(Date.now() + 3_600_000) }],
		]);
		const h = makeHarness({
			tokenExchange: { enabled: true },
			delegationStore: { findLink: async (from, to) => links.get(`${from}>${to}`) ?? null },
		});
		await addClient(h, { clientId: "app" });
		await addClient(h, { clientId: "xch", secret: "s", grantTypes: [TE] });
		const subject = await codeFlow(h, "app");
		const exchanged = await h.mcp.token(
			tokenRequest(
				{ grant_type: TE, subject_token: subject.access_token, subject_token_type: AT },
				basicAuth("xch", "s"),
			),
		);
		if (!exchanged.success) throw new Error(exchanged.error.message);
		const token = exchanged.data.access_token;
		expect((await h.mcp.requireScopes(req(token), ["mcp:read"])).authorized).toBe(true);
		links.set("user_1>xch", { status: "revoked", expiresAt: new Date(Date.now() + 3_600_000) });
		const res = await h.mcp.requireScopes(req(token), ["mcp:read"]);
		expect(res.authorized).toBe(false);
		if (res.authorized) return;
		expect(res.status).toBe(401);
		expect(res.error.code).toBe("DELEGATION_REVOKED");
		expect(res.rejected?.clientId).toBe("xch");
		expect(res.rejected?.subject).toBe("user_1");
	});

	it("authorizes a good token", async () => {
		const { mcp } = makeHarness();
		const res = await mcp.requireScopes(req(await sign({ scope: "mcp:read mcp:write" })), [
			"mcp:read",
			"mcp:write",
		]);
		expect(res.authorized).toBe(true);
		if (res.authorized) expect(res.session.clientId).toBe("client-a");
	});

	it("requireMcpAuth names the needed scope on its 401 challenge too", async () => {
		const { mcp } = makeHarness();
		const handler = mcp.requireMcpAuth(async () => new Response("ok"), {
			requiredScopes: ["mcp:read"],
		});
		const res = await handler(req());
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toContain('scope="mcp:read"');
		expect(res.headers.get("www-authenticate")).toContain("resource_metadata=");
	});
});
