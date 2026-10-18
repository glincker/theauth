/** Strict Client ID Metadata Document validation table. */
import { describe, expect, it } from "vitest";
import {
	buildCimdSnapshot,
	computeCimdDigest,
	validateCimdDocument,
} from "../src/mcp/cimd-document.js";

const ID = "https://app.example.com/oauth/client.json";
const CB = "https://app.example.com/cb";
const JWK = { kty: "EC", crv: "P-256", x: "AAAA", y: "BBBB", kid: "k1" };

function doc(extra: Record<string, unknown> = {}): Record<string, unknown> {
	return { client_id: ID, redirect_uris: [CB], ...extra };
}

/** Builds an object whose own property is literally `__proto__`, as JSON.parse does. */
const protoDoc = (): unknown =>
	JSON.parse(`{"client_id":"${ID}","redirect_uris":["${CB}"],"__proto__":{"a":1}}`);

const longStr = (n: number) => "a".repeat(n);
const many = (n: number) => Array.from({ length: n }, (_, i) => `https://app.example.com/cb${i}`);

describe("validateCimdDocument rejections", () => {
	const rejected: Array<[string, unknown, string]> = [
		["null", null, "document"],
		["array", [doc()], "document"],
		["string", "x", "document"],
		["number", 1, "document"],
		["class instance", new Date(), "document"],
		["missing client_id", { redirect_uris: [CB] }, "client_id"],
		["client_id trailing slash", doc({ client_id: `${ID}/` }), "client_id"],
		[
			"client_id other host",
			doc({ client_id: "https://evil.example.com/oauth/client.json" }),
			"client_id",
		],
		["client_id uppercase", doc({ client_id: ID.toUpperCase() }), "client_id"],
		["client_id number", doc({ client_id: 5 }), "client_id"],
		["client_id array", doc({ client_id: [ID] }), "client_id"],
		["missing redirect_uris", { client_id: ID }, "redirect_uris"],
		["empty redirect_uris", doc({ redirect_uris: [] }), "redirect_uris"],
		["redirect_uris string", doc({ redirect_uris: CB }), "redirect_uris"],
		["redirect_uris non strings", doc({ redirect_uris: [1] }), "redirect_uris"],
		["11 redirect uris", doc({ redirect_uris: many(11) }), "redirect_uris"],
		[
			"2049 char redirect uri",
			doc({ redirect_uris: [`https://app.example.com/${longStr(2030)}`] }),
			"redirect_uris",
		],
		[
			"http redirect non loopback",
			doc({ redirect_uris: ["http://app.example.com/cb"] }),
			"redirect_uris",
		],
		["custom scheme redirect", doc({ redirect_uris: ["myapp://cb"] }), "redirect_uris"],
		["javascript redirect", doc({ redirect_uris: ["javascript:alert(1)"] }), "redirect_uris"],
		["redirect with fragment", doc({ redirect_uris: [`${CB}#f`] }), "redirect_uris"],
		[
			"redirect with userinfo",
			doc({ redirect_uris: ["https://u:p@app.example.com/cb"] }),
			"redirect_uris",
		],
		[
			"redirect with wildcard",
			doc({ redirect_uris: ["https://*.example.com/cb"] }),
			"redirect_uris",
		],
		[
			"redirect with space",
			doc({ redirect_uris: ["https://app.example.com/c b"] }),
			"redirect_uris",
		],
		[
			"redirect with backslash",
			doc({ redirect_uris: ["https://app.example.com\\@evil.com/cb"] }),
			"redirect_uris",
		],
		["redirect with newline", doc({ redirect_uris: [`${CB}\n`] }), "redirect_uris"],
		["redirect relative", doc({ redirect_uris: ["/cb"] }), "redirect_uris"],
		["redirect empty string", doc({ redirect_uris: [""] }), "redirect_uris"],
		[
			"http on lookalike localhost",
			doc({ redirect_uris: ["http://localhost.evil.com/cb"] }),
			"redirect_uris",
		],
		["http on 127.0.0.2", doc({ redirect_uris: ["http://127.0.0.2/cb"] }), "redirect_uris"],
		["duplicate redirect uris", doc({ redirect_uris: [CB, CB] }), "redirect_uris"],
		[
			"client_secret_basic",
			doc({ token_endpoint_auth_method: "client_secret_basic" }),
			"token_endpoint_auth_method",
		],
		[
			"client_secret_post",
			doc({ token_endpoint_auth_method: "client_secret_post" }),
			"token_endpoint_auth_method",
		],
		[
			"client_secret_jwt",
			doc({ token_endpoint_auth_method: "client_secret_jwt" }),
			"token_endpoint_auth_method",
		],
		[
			"tls_client_auth",
			doc({ token_endpoint_auth_method: "tls_client_auth" }),
			"token_endpoint_auth_method",
		],
		[
			"unknown auth method",
			doc({ token_endpoint_auth_method: "magic" }),
			"token_endpoint_auth_method",
		],
		[
			"auth method uppercase none",
			doc({ token_endpoint_auth_method: "NONE" }),
			"token_endpoint_auth_method",
		],
		[
			"auth method array",
			doc({ token_endpoint_auth_method: ["none"] }),
			"token_endpoint_auth_method",
		],
		["client_secret field", doc({ client_secret: "x" }), "client_secret"],
		["client_secret_expires_at", doc({ client_secret_expires_at: 0 }), "client_secret_expires_at"],
		["Client_Secret mixed case", doc({ Client_Secret: "x" }), "Client_Secret"],
		["client-secret dashed", doc({ "client-secret": "x" }), "client-secret"],
		["client_secret_something", doc({ client_secret_hash: "x" }), "client_secret_hash"],
		[
			"registration_access_token",
			doc({ registration_access_token: "x" }),
			"registration_access_token",
		],
		[
			"registration_client_uri",
			doc({ registration_client_uri: "https://x.example.com" }),
			"registration_client_uri",
		],
		["agent_id smuggled", doc({ agent_id: "agent_1" }), "agent_id"],
		["agentId smuggled", doc({ agentId: "agent_1" }), "agentId"],
		["Agent-Id smuggled", doc({ "Agent-Id": "agent_1" }), "Agent-Id"],
		["agent object smuggled", doc({ agent: { id: "a" } }), "agent"],
		["admin flag", doc({ admin: true }), "admin"],
		["disabled false", doc({ disabled: false }), "disabled"],
		["disabled_reason", doc({ disabled_reason: "x" }), "disabled_reason"],
		["user_id", doc({ user_id: "u1" }), "user_id"],
		["source", doc({ source: "preregistered" }), "source"],
		["client_type", doc({ client_type: "confidential" }), "client_type"],
		["theauth_ member", doc({ theauth_agent: "a" }), "theauth_agent"],
		["x-theauth member", doc({ "x-theauth-scope": "a" }), "x-theauth-scope"],
		["crit member", doc({ crit: ["x"] }), "crit"],
		["__proto__ own key", protoDoc(), "__proto__"],
		[
			"65 top level keys",
			{ ...doc(), ...Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`k${i}`, 1])) },
			"document",
		],
		[
			"deeply nested unknown member",
			doc({ x: JSON.parse(`${"[".repeat(12)}${"]".repeat(12)}`) }),
			"document",
		],
		[
			"private_key_jwt without keys",
			doc({ token_endpoint_auth_method: "private_key_jwt" }),
			"jwks",
		],
		[
			"jwks and jwks_uri",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks: { keys: [JWK] },
				jwks_uri: "https://app.example.com/j",
			}),
			"jwks",
		],
		["jwks with none", doc({ jwks: { keys: [JWK] } }), "jwks"],
		["jwks_uri with none", doc({ jwks_uri: "https://app.example.com/j" }), "jwks"],
		[
			"jwks private d",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [{ ...JWK, d: "x" }] } }),
			"jwks",
		],
		[
			"jwks symmetric k",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks: { keys: [{ kty: "oct", k: "x" }] },
			}),
			"jwks",
		],
		[
			"jwks oct kty",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [{ kty: "oct" }] } }),
			"jwks",
		],
		[
			"jwks empty",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [] } }),
			"jwks",
		],
		[
			"jwks not object",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: [JWK] }),
			"jwks",
		],
		[
			"jwks 11 keys",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks: { keys: Array.from({ length: 11 }, (_, i) => ({ ...JWK, kid: `k${i}` })) },
			}),
			"jwks",
		],
		[
			"jwks duplicate kid",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [JWK, JWK] } }),
			"jwks",
		],
		[
			"jwks long kid",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks: { keys: [{ ...JWK, kid: longStr(300) }] },
			}),
			"jwks",
		],
		[
			"jwks_uri http",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "http://app.example.com/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri localhost",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://localhost/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri private ip",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://10.0.0.5/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri metadata ip",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://169.254.169.254/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri internal host",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://db.internal/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri nip.io",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://10.0.0.1.nip.io/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri single label",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://intranet/j" }),
			"jwks_uri",
		],
		[
			"jwks_uri userinfo",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks_uri: "https://u@app.example.com/j",
			}),
			"jwks_uri",
		],
		[
			"jwks_uri port",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks_uri: "https://app.example.com:8443/j",
			}),
			"jwks_uri",
		],
		[
			"jwks_uri number",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: 5 }),
			"jwks_uri",
		],
		[
			"jwks_uri garbage",
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "not a url" }),
			"jwks_uri",
		],
		["grant client_credentials", doc({ grant_types: ["client_credentials"] }), "grant_types"],
		["grant implicit", doc({ grant_types: ["authorization_code", "implicit"] }), "grant_types"],
		["grant refresh only", doc({ grant_types: ["refresh_token"] }), "grant_types"],
		["grant empty", doc({ grant_types: [] }), "grant_types"],
		["grant string", doc({ grant_types: "authorization_code" }), "grant_types"],
		[
			"grant duplicate",
			doc({ grant_types: ["authorization_code", "authorization_code"] }),
			"grant_types",
		],
		["response_types token", doc({ response_types: ["token"] }), "response_types"],
		["response_types code token", doc({ response_types: ["code", "token"] }), "response_types"],
		["response_types string", doc({ response_types: "code" }), "response_types"],
		["client_name number", doc({ client_name: 5 }), "client_name"],
		["client_name 201 chars", doc({ client_name: longStr(201) }), "client_name"],
		["client_name object", doc({ client_name: { en: "x" } }), "client_name"],
		["logo_uri number", doc({ logo_uri: 5 }), "logo_uri"],
		["scope too long", doc({ scope: longStr(1025) }), "scope"],
		["scope double space", doc({ scope: "a  b" }), "scope"],
		["scope with quote", doc({ scope: 'a"b' }), "scope"],
		["scope array", doc({ scope: ["a"] }), "scope"],
		[
			"6 contacts",
			doc({ contacts: Array.from({ length: 6 }, (_, i) => `a${i}@example.com`) }),
			"contacts",
		],
		["contact too long", doc({ contacts: [longStr(255)] }), "contacts"],
		["contacts string", doc({ contacts: "a@example.com" }), "contacts"],
		["software_id too long", doc({ software_id: longStr(256) }), "software_id"],
		["software_version number", doc({ software_version: 1 }), "software_version"],
	];

	it("holds at least 60 rejection rows", () => {
		expect(rejected.length).toBeGreaterThanOrEqual(60);
	});

	it.each(rejected)("rejects: %s", async (_name, input, field) => {
		const res = await validateCimdDocument(ID, input);
		expect(res.ok).toBe(false);
		if (!res.ok) expect(res.field).toBe(field);
	});
});

describe("validateCimdDocument acceptance", () => {
	const accepted: Array<[string, Record<string, unknown>]> = [
		["minimal", doc()],
		["auth none", doc({ token_endpoint_auth_method: "none" })],
		["loopback localhost http", doc({ redirect_uris: ["http://localhost:3000/cb"] })],
		["loopback 127.0.0.1 http", doc({ redirect_uris: ["http://127.0.0.1:8080/cb"] })],
		["loopback ipv6 http", doc({ redirect_uris: ["http://[::1]:8080/cb"] })],
		["10 redirect uris", doc({ redirect_uris: many(10) })],
		["inline jwks", doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [JWK] } })],
		[
			"jwks_uri",
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks_uri: "https://keys.example.com/j.json",
			}),
		],
		["both grants", doc({ grant_types: ["authorization_code", "refresh_token"] })],
		["code grant only", doc({ grant_types: ["authorization_code"] })],
		["response_types code", doc({ response_types: ["code"] })],
		[
			"unknown members ignored",
			doc({ some_extension: { nested: [1, 2] }, application_type: "web" }),
		],
		["scope", doc({ scope: "mcp:read mcp:write" })],
		["contacts", doc({ contacts: ["ops@example.com"] })],
		["200 char name", doc({ client_name: longStr(200) })],
	];

	it.each(accepted)("accepts: %s", async (_name, input) => {
		const res = await validateCimdDocument(ID, input);
		expect(res.ok).toBe(true);
	});

	it("derives public and confidential clients with a null secret and no agent", async () => {
		const pub = await validateCimdDocument(ID, doc());
		const conf = await validateCimdDocument(
			ID,
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [JWK] } }),
		);
		if (!pub.ok || !conf.ok) throw new Error("expected valid documents");
		expect(pub.client).toMatchObject({
			clientType: "public",
			tokenEndpointAuthMethod: "none",
			clientSecret: null,
			source: "cimd",
			disabled: false,
			userId: null,
			grantTypes: ["authorization_code", "refresh_token"],
		});
		expect(pub.client.agentId).toBeUndefined();
		expect(conf.client).toMatchObject({
			clientType: "confidential",
			tokenEndpointAuthMethod: "private_key_jwt",
		});
		expect(conf.client.jwks?.keys).toHaveLength(1);
	});

	it("strips bidi overrides and controls from client_name, empty becomes null", async () => {
		const res = await validateCimdDocument(ID, doc({ client_name: "Ap‮p⁦ \u0000One​" }));
		if (!res.ok) throw new Error("expected valid");
		expect(res.client.clientName).toBe("App One");
		const empty = await validateCimdDocument(ID, doc({ client_name: " ‮ " }));
		if (!empty.ok) throw new Error("expected valid");
		expect(empty.client.clientName).toBeNull();
	});

	it("drops non https and oversized display URIs instead of rejecting", async () => {
		const res = await validateCimdDocument(
			ID,
			doc({
				client_uri: "http://app.example.com",
				logo_uri: `https://app.example.com/${longStr(2100)}`,
				tos_uri: "javascript:alert(1)",
				policy_uri: "https://app.example.com/policy",
			}),
		);
		if (!res.ok) throw new Error("expected valid");
		expect(res.client).toMatchObject({
			clientUri: null,
			logoUri: null,
			tosUri: null,
			policyUri: "https://app.example.com/policy",
		});
	});

	it("honors deniedHosts for jwks_uri", async () => {
		const res = await validateCimdDocument(
			ID,
			doc({
				token_endpoint_auth_method: "private_key_jwt",
				jwks_uri: "https://keys.evil.example.com/j",
			}),
			{ hostPolicy: { deniedHosts: ["*.evil.example.com"] } },
		);
		expect(res.ok).toBe(false);
	});
});

describe("snapshot and digest", () => {
	it("builds a snapshot with fetch and expiry times and the raw document", async () => {
		const now = new Date("2026-10-12T00:00:00Z");
		const input = doc({ some_extension: 1 });
		const res = await validateCimdDocument(ID, input, { now, cacheSeconds: 300 });
		if (!res.ok) throw new Error("expected valid");
		expect(res.client.cimd).toEqual({
			digest: res.digest,
			fetchedAt: now,
			expiresAt: new Date("2026-10-12T00:05:00Z"),
			document: input,
		});
		expect(buildCimdSnapshot(input, "d", now, 60).expiresAt.getTime()).toBe(now.getTime() + 60000);
	});

	it("digest ignores display fields and member order but tracks trust fields", async () => {
		const a = await validateCimdDocument(ID, doc({ client_name: "A" }));
		const b = await validateCimdDocument(ID, {
			redirect_uris: [CB],
			client_name: "B",
			client_id: ID,
		});
		const c = await validateCimdDocument(
			ID,
			doc({ redirect_uris: [CB, "https://app.example.com/other"] }),
		);
		const d = await validateCimdDocument(
			ID,
			doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [JWK] } }),
		);
		if (!a.ok || !b.ok || !c.ok || !d.ok) throw new Error("expected valid");
		expect(a.digest).toBe(b.digest);
		expect(a.digest).toMatch(/^[0-9a-f]{64}$/);
		expect(new Set([a.digest, c.digest, d.digest]).size).toBe(3);
		const direct = await computeCimdDigest({
			redirectUris: [CB],
			tokenEndpointAuthMethod: "none",
			grantTypes: ["authorization_code", "refresh_token"],
		});
		expect(direct).toBe(a.digest);
	});
});
