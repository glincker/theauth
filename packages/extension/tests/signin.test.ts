import { describe, expect, it } from "vitest";
import { metadataUrl } from "../src/discovery.js";
import { s256Challenge } from "../src/encoding.js";
import { createExtensionAuth, ExtensionAuthError } from "../src/index.js";
import {
	approve,
	baseOptions,
	fakeIdentity,
	fakeServer,
	fakeStorage,
	REDIRECT,
	tokenCalls,
	tokenJson,
} from "./helpers.js";

async function codeOf(p: Promise<unknown>): Promise<string> {
	try {
		await p;
	} catch (e) {
		if (e instanceof ExtensionAuthError) return e.code;
		throw e;
	}
	return "none";
}

describe("PKCE", () => {
	it("matches the RFC 7636 appendix B vector", async () => {
		expect(await s256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
			"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		);
	});
});

describe("sign in", () => {
	it("sends S256, state, resource and redirect, then exchanges the matching verifier", async () => {
		const server = fakeServer();
		const identity = fakeIdentity(approve());
		const auth = createExtensionAuth(
			baseOptions(server, fakeStorage(), {
				identity,
				resource: "https://api.example.test",
				scopes: ["openid", "read"],
			}),
		);
		const session = await auth.signIn();
		expect(session.tokenType).toBe("Bearer");

		const url = new URL(identity.urls[0] ?? "");
		expect(url.origin + url.pathname).toBe("https://auth.example.test/authorize");
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT);
		expect(url.searchParams.get("resource")).toBe("https://api.example.test");
		expect(url.searchParams.get("nonce")).toBeTruthy();
		expect(url.searchParams.get("state")?.length).toBeGreaterThan(16);

		const exchange = tokenCalls(server)[0];
		expect(exchange?.params.get("grant_type")).toBe("authorization_code");
		expect(exchange?.params.get("resource")).toBe("https://api.example.test");
		const verifier = exchange?.params.get("code_verifier") ?? "";
		expect(await s256Challenge(verifier)).toBe(url.searchParams.get("code_challenge"));
	});

	it("rejects a state mismatch without calling the token endpoint", async () => {
		const server = fakeServer();
		const identity = fakeIdentity(() => `${REDIRECT}?code=c&state=wrong`);
		const auth = createExtensionAuth(baseOptions(server, fakeStorage(), { identity }));
		expect(await codeOf(auth.signIn())).toBe("state_mismatch");
		expect(tokenCalls(server)).toHaveLength(0);
	});

	it("rejects a missing state", async () => {
		const server = fakeServer();
		const identity = fakeIdentity(() => `${REDIRECT}?code=c`);
		const auth = createExtensionAuth(baseOptions(server, fakeStorage(), { identity }));
		expect(await codeOf(auth.signIn())).toBe("state_mismatch");
	});

	it("maps a closed window to user_cancelled", async () => {
		const server = fakeServer();
		const identity = fakeIdentity(() => {
			throw new Error("The user did not approve access.");
		});
		const auth = createExtensionAuth(baseOptions(server, fakeStorage(), { identity }));
		expect(await codeOf(auth.signIn())).toBe("user_cancelled");
	});

	it("maps access_denied and an empty result to user_cancelled", async () => {
		const server = fakeServer();
		const denied = fakeIdentity((u) => {
			return `${REDIRECT}?error=access_denied&state=${u.searchParams.get("state")}`;
		});
		const a = createExtensionAuth(baseOptions(server, fakeStorage(), { identity: denied }));
		expect(await codeOf(a.signIn())).toBe("user_cancelled");
		const empty = fakeIdentity(() => undefined);
		const b = createExtensionAuth(baseOptions(server, fakeStorage(), { identity: empty }));
		expect(await codeOf(b.signIn())).toBe("user_cancelled");
	});

	it("rejects a mismatched iss parameter", async () => {
		const server = fakeServer();
		const identity = fakeIdentity(approve({ iss: "https://evil.example.test" }));
		const auth = createExtensionAuth(baseOptions(server, fakeStorage(), { identity }));
		expect(await codeOf(auth.signIn())).toBe("authorization_failed");
	});

	it("reports token_exchange_failed on a rejected code", async () => {
		const server = fakeServer();
		server.onToken = () => Response.json({ error: "invalid_grant" }, { status: 400 });
		const auth = createExtensionAuth(baseOptions(server, fakeStorage()));
		expect(await codeOf(auth.signIn())).toBe("token_exchange_failed");
	});

	it("rejects an ID token with the wrong nonce and stores nothing", async () => {
		const server = fakeServer();
		const claims = btoa(JSON.stringify({ nonce: "other" })).replace(/=+$/, "");
		server.onToken = () => tokenJson({ id_token: `e30.${claims}.sig` });
		const storage = fakeStorage();
		const auth = createExtensionAuth(baseOptions(server, storage, { scopes: ["openid"] }));
		expect(await codeOf(auth.signIn())).toBe("token_exchange_failed");
		expect(await auth.getSession()).toBeNull();
	});

	it("stores access in session storage and refresh in local storage", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		const auth = createExtensionAuth(baseOptions(server, storage));
		await auth.signIn();
		const session = JSON.stringify(await storage.session.get(["theauth:ext:ext-client:access"]));
		const local = JSON.stringify(await storage.local.get(["theauth:ext:ext-client:refresh"]));
		expect(session).toContain("at-1");
		expect(session).not.toContain("rt-1");
		expect(local).toContain("rt-1");
		expect(local).not.toContain("at-1");
	});
});

describe("discovery", () => {
	it("builds RFC 8414 URLs for issuers with and without a path", () => {
		expect(metadataUrl("https://a.test")).toBe(
			"https://a.test/.well-known/oauth-authorization-server",
		);
		expect(metadataUrl("https://a.test/tenant/1")).toBe(
			"https://a.test/.well-known/oauth-authorization-server/tenant/1",
		);
	});

	it("fails with discovery_failed when metadata is unreachable or the issuer differs", async () => {
		const down = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
		const a = createExtensionAuth(baseOptions(fakeServer(), fakeStorage(), { fetch: down }));
		expect(await codeOf(a.signIn())).toBe("discovery_failed");

		const other = (async () =>
			Response.json({
				issuer: "https://other.test",
				authorization_endpoint: "https://other.test/a",
				token_endpoint: "https://other.test/t",
			})) as unknown as typeof fetch;
		const b = createExtensionAuth(baseOptions(fakeServer(), fakeStorage(), { fetch: other }));
		expect(await codeOf(b.signIn())).toBe("discovery_failed");
	});

	it("skips discovery when endpoints are passed", async () => {
		const server = fakeServer();
		const auth = createExtensionAuth(
			baseOptions(server, fakeStorage(), {
				issuer: undefined,
				endpoints: {
					authorization: `${"https://x.test"}/authorize`,
					token: "https://x.test/token",
				},
			}),
		);
		await auth.signIn();
		expect(server.calls[0]?.url).toBe("https://x.test/token");
	});
});
