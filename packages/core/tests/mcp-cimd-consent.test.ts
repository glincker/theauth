/** CIMD consent gate, the consent view model, admin blocks and agent binding. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { oauthAccessTokens } from "../src/db/schema.js";
import { handleAuthorize } from "../src/mcp/authorize.js";
import { createInMemoryJtiDenylist } from "../src/mcp/memory-stores.js";
import { createMcpModule } from "../src/mcp/server.js";
import type { McpAuthContext, McpConfig } from "../src/mcp/types.js";
import type { ConsentWarning } from "../src/mcp/types-cimd.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import { bootDb, mcpConfig } from "./mcp-db-harness.js";
import type { Harness } from "./mcp-test-harness.js";
import {
	addClient,
	BASE_URL,
	decodePayload,
	ISSUER,
	makeHarness,
	REDIRECT,
	RESOURCE,
	SECRET,
	tokenRequest,
	USER,
} from "./mcp-test-harness.js";

const CONSENT = "https://auth.example.com/consent";
const HOST = "client.example.com";
const CLIENT_ID = `https://${HOST}/metadata.json`;

type Doc = Record<string, unknown>;

function docFor(clientId: string, extra: Doc = {}): Doc {
	return { client_id: clientId, redirect_uris: [REDIRECT], client_name: "My App", ...extra };
}

/** Serves each document by URL and counts the fetches. */
function docs(routes: Record<string, Doc>) {
	const calls: string[] = [];
	const fetchImpl = (async (url: string) => {
		calls.push(url);
		const body = routes[url];
		if (!body) return new Response("nope", { status: 404 });
		return new Response(JSON.stringify(body), {
			status: 200,
			headers: { "content-type": "application/json", "cache-control": "max-age=3600" },
		});
	}) as unknown as typeof fetch;
	return { calls, fetchImpl, routes };
}

function cimdConfig(
	fetchImpl: typeof fetch,
	extra: Partial<McpConfig> = {},
	cimd: Partial<NonNullable<McpConfig["clientIdMetadataDocuments"]>> = {},
): Partial<McpConfig> {
	return {
		consentPage: CONSENT,
		clientIdMetadataDocuments: {
			enabled: true,
			resolver: async () => ["93.184.216.34"],
			fetchImpl,
			...cimd,
		},
		...extra,
	};
}

function authorizeUrl(clientId: string, redirectUri = REDIRECT, state = "st1"): Request {
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const params: Record<string, string> = {
		response_type: "code",
		client_id: clientId,
		redirect_uri: redirectUri,
		scope: "mcp:read offline_access",
		state,
		code_challenge: "x".repeat(43),
		code_challenge_method: "S256",
		resource: RESOURCE,
	};
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
	return new Request(url);
}

/** A full code flow through the consent page: authorize, approveConsent, token. */
async function issueTokens(mcp: Harness["mcp"], clientId: string, userId = USER) {
	const verifier = generateSecureToken(43);
	const challenge = await computeS256Challenge(verifier);
	const approved = await mcp.approveConsent({
		userId,
		clientId,
		scope: "mcp:read offline_access",
		redirectUri: REDIRECT,
		codeChallenge: challenge,
		codeChallengeMethod: "S256",
		resource: RESOURCE,
	});
	if (!approved.success) throw new Error(approved.error.message);
	const code = new URL(approved.data.redirectUri).searchParams.get("code") ?? "";
	const res = await mcp.token(
		tokenRequest({
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			client_id: clientId,
			code_verifier: verifier,
			resource: RESOURCE,
		}),
	);
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data;
}

describe("CIMD requires a consent page", () => {
	const base = {
		issuer: ISSUER,
		baseUrl: BASE_URL,
		signingSecret: SECRET,
	};
	const stores = {
		storeClient: async () => {},
		findClient: async () => null,
		storeAuthorizationCode: async () => {},
		consumeAuthorizationCode: async () => null,
		storeToken: async () => {},
		findTokenByRefreshToken: async () => null,
		revokeToken: async () => {},
		resolveUserId: async () => USER,
	};

	it("throws at startup when CIMD is on and consentPage is missing", () => {
		expect(() =>
			createMcpModule({
				...stores,
				config: { enabled: true, ...base, clientIdMetadataDocuments: { enabled: true } },
			}),
		).toThrow(/consentPage is required/);
	});

	it("starts with a consentPage, and CIMD off needs none", () => {
		expect(() =>
			createMcpModule({
				...stores,
				config: {
					enabled: true,
					...base,
					consentPage: CONSENT,
					clientIdMetadataDocuments: { enabled: true },
				},
			}),
		).not.toThrow();
		expect(() => createMcpModule({ ...stores, config: { enabled: true, ...base } })).not.toThrow();
	});

	it("never auto approves a CIMD client even when consentPage disappears later", async () => {
		const s = docs({ [CLIENT_ID]: docFor(CLIENT_ID) });
		const h = makeHarness(cimdConfig(s.fetchImpl));
		const first = await h.mcp.authorize(authorizeUrl(CLIENT_ID));
		expect(first.success && first.data.redirectUri.startsWith(CONSENT)).toBe(true);
		expect(first.success && first.data.code).toBe("");

		// The handler is also reachable with a context whose config lost its consent page.
		const stored = h.clients.get(CLIENT_ID);
		if (!stored) throw new Error("client was not stored");
		const ctx: McpAuthContext = {
			config: {
				issuer: ISSUER,
				baseUrl: BASE_URL,
				accessTokenTtl: 3600,
				refreshTokenTtl: 3600,
				refreshTokenAbsoluteTtl: 3600,
				codeTtl: 600,
				enabled: true,
				resource: RESOURCE,
				scopes: ["mcp:read", "offline_access"],
				clientIdMetadataDocuments: { enabled: true, resolver: async () => ["93.184.216.34"] },
			},
			storeClient: async () => {},
			findClient: async () => stored,
			storeAuthorizationCode: async () => {
				throw new Error("a code must never be stored without consent");
			},
			consumeAuthorizationCode: async () => null,
			storeToken: async () => {},
			findTokenByRefreshToken: async () => null,
			revokeToken: async () => {},
			resolveUserId: async () => USER,
		};
		const res = await handleAuthorize(ctx, authorizeUrl(CLIENT_ID));
		expect(res.success).toBe(false);
		expect(!res.success && res.error.code).toBe("CONSENT_REQUIRED");
	});
});

describe("state and redirect tampering", () => {
	it("hands state, client_id and the registered redirect to the consent page unchanged", async () => {
		const s = docs({ [CLIENT_ID]: docFor(CLIENT_ID) });
		const h = makeHarness(cimdConfig(s.fetchImpl));
		const res = await h.mcp.authorize(authorizeUrl(CLIENT_ID, REDIRECT, "abc 123&x=1"));
		if (!res.success) throw new Error(res.error.message);
		const consent = new URL(res.data.redirectUri);
		expect(consent.origin + consent.pathname).toBe(CONSENT);
		expect(consent.searchParams.get("state")).toBe("abc 123&x=1");
		expect(consent.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(consent.searchParams.get("redirect_uri")).toBe(REDIRECT);
		expect(h.codes.size).toBe(0);
	});

	it("rejects a redirect_uri the document did not list, including near misses", async () => {
		const s = docs({ [CLIENT_ID]: docFor(CLIENT_ID) });
		const h = makeHarness(cimdConfig(s.fetchImpl));
		for (const uri of [
			"https://evil.example.org/callback",
			`${REDIRECT}/`,
			`${REDIRECT}?x=1`,
			REDIRECT.replace("https:", "http:"),
		]) {
			const res = await h.mcp.authorize(authorizeUrl(CLIENT_ID, uri));
			expect(res.success).toBe(false);
			expect(!res.success && res.error.code).toBe("INVALID_REDIRECT_URI");
		}
	});

	it("approveConsent with a tampered redirect_uri issues nothing", async () => {
		const s = docs({ [CLIENT_ID]: docFor(CLIENT_ID) });
		const h = makeHarness(cimdConfig(s.fetchImpl));
		const res = await h.mcp.approveConsent({
			userId: USER,
			clientId: CLIENT_ID,
			scope: "mcp:read",
			redirectUri: "https://evil.example.org/callback",
			codeChallenge: "x".repeat(43),
			codeChallengeMethod: "S256",
			resource: RESOURCE,
		});
		expect(res.success).toBe(false);
		expect(h.codes.size).toBe(0);
	});
});

describe("describeClient", () => {
	const idn = "https://xn--bcher-kva.example/metadata.json";
	const loopback = "https://loopback.example.com/metadata.json";
	const otherRedirect = "https://redirect.example.com/metadata.json";
	const named = "https://named.example.com/metadata.json";
	const uriDiffers = "https://uri.example.com/metadata.json";
	const plain = "https://plain.example.com/metadata.json";
	const routes: Record<string, Doc> = {
		[plain]: docFor(plain, { redirect_uris: ["https://plain.example.com/cb"] }),
		[CLIENT_ID]: docFor(CLIENT_ID, {
			redirect_uris: [`https://app.${HOST}/cb`],
			logo_uri: "https://client.example.com/logo.png",
		}),
		[idn]: docFor(idn, { redirect_uris: ["https://xn--bcher-kva.example/cb"] }),
		[loopback]: docFor(loopback, { redirect_uris: ["http://localhost:3000/cb"] }),
		[otherRedirect]: docFor(otherRedirect, { redirect_uris: ["https://elsewhere.example.org/cb"] }),
		[named]: docFor(named, {
			redirect_uris: ["https://named.example.com/cb"],
			client_name: "Sign in with login.bank.com",
		}),
		[uriDiffers]: docFor(uriDiffers, {
			redirect_uris: ["https://uri.example.com/cb"],
			client_uri: "https://marketing.example.net/",
		}),
	};

	const table: Array<[string, string, ConsentWarning[]]> = [
		["a clean client", plain, []],
		["redirect on another host", otherRedirect, ["redirect_host_differs"]],
		["loopback http redirect", loopback, ["localhost_redirect", "http_redirect"]],
		["punycode host", idn, ["idn_host"]],
		["name mentions another host", named, ["name_mentions_other_host"]],
		["client_uri on another host", uriDiffers, ["client_uri_host_differs"]],
	];

	it.each(table)("%s", async (_label, clientId, expected) => {
		const h = makeHarness(cimdConfig(docs(routes).fetchImpl));
		const res = await h.mcp.describeClient(clientId);
		if (!res.success) throw new Error(res.error.message);
		expect([...res.data.warnings].sort()).toEqual([...expected].sort());
		expect(res.data.source).toBe("cimd");
		expect(res.data.clientId).toBe(clientId);
	});

	it("shows the verified host as identity and the name only as secondary text", async () => {
		const h = makeHarness(cimdConfig(docs(routes).fetchImpl));
		const res = await h.mcp.describeClient(idn);
		if (!res.success) throw new Error(res.error.message);
		expect(res.data.verifiedHost).toBe("xn--bcher-kva.example");
		expect(res.data.clientName).toBe("My App");
		const sub = await h.mcp.describeClient(CLIENT_ID);
		if (!sub.success) throw new Error(sub.error.message);
		expect(sub.data.verifiedHost).toBe(HOST);
		expect(sub.data.redirectHost).toBe(`app.${HOST}`);
		expect(sub.data.warnings).toEqual([]);
		expect(sub.data.logoUri).toBe("https://client.example.com/logo.png");
	});

	it("adds first_use when the app says so, and describes the redirect it is given", async () => {
		const h = makeHarness(cimdConfig(docs(routes).fetchImpl));
		const res = await h.mcp.describeClient(plain, "https://plain.example.com/cb", {
			firstUse: true,
		});
		expect(res.success && res.data.warnings).toEqual(["first_use"]);
		const bad = await h.mcp.describeClient(plain, "https://evil.example.org/cb");
		expect(!bad.success && bad.error.code).toBe("INVALID_REDIRECT_URI");
	});

	it("flags a document that was re-read and changed recently", async () => {
		const h = makeHarness(cimdConfig(docs(routes).fetchImpl));
		await h.mcp.describeClient(plain);
		const stored = h.clients.get(plain);
		if (!stored) throw new Error("not stored");
		stored.createdAt = new Date(Date.now() - 3_600_000);
		const res = await h.mcp.describeClient(plain);
		expect(res.success && res.data.warnings).toContain("recently_changed");
	});

	it("describes non CIMD clients without a verified host, and refuses unknown or disabled ones", async () => {
		const h = makeHarness(cimdConfig(docs(routes).fetchImpl));
		await addClient(h, { clientId: "dcr_1" });
		const dcr = await h.mcp.describeClient("dcr_1");
		expect(dcr.success && dcr.data.verifiedHost).toBeNull();
		expect(dcr.success && dcr.data.source).toBe("dcr");
		const unknown = await h.mcp.describeClient("https://nowhere.example.com/m.json");
		expect(!unknown.success && unknown.error.code).toBe("INVALID_CLIENT");
		const stored = h.clients.get("dcr_1");
		if (stored) stored.disabled = true;
		const off = await h.mcp.describeClient("dcr_1");
		expect(off.success).toBe(false);
	});

	it("marks pre-registered clients and bound clients", async () => {
		const h = makeHarness({
			...cimdConfig(docs(routes).fetchImpl),
			preRegisteredClients: [{ clientId: "pre_1", redirectUris: [REDIRECT], agentId: "agent_1" }],
		});
		await new Promise((r) => setTimeout(r, 10));
		const res = await h.mcp.describeClient("pre_1");
		expect(res.success && res.data.source).toBe("preregistered");
		expect(res.success && res.data.warnings).toContain("bound_to_agent");
		expect(res.success && res.data.agentId).toBe("agent_1");
	});
});

describe("agent binding is admin only", () => {
	it("rejects a document that names an agent, so a client cannot bind itself", async () => {
		const s = docs({ [CLIENT_ID]: docFor(CLIENT_ID, { agent_id: "agent_victim" }) });
		const h = makeHarness(cimdConfig(s.fetchImpl));
		const res = await h.mcp.authorize(authorizeUrl(CLIENT_ID));
		expect(res.success).toBe(false);
		expect(h.clients.has(CLIENT_ID)).toBe(false);
	});

	it("bindAgent on a never seen URL fetches it first, then binds; tokens carry agent_id", async () => {
		const d = await bootDb();
		const s = docs({ [CLIENT_ID]: docFor(CLIENT_ID) });
		const mcp = createMcpModule({
			auth: d.auth,
			config: { ...mcpConfig(cimdConfig(s.fetchImpl)), jtiDenylist: createInMemoryJtiDenylist() },
			resolveUserId: async () => d.userId,
		});
		const agent = await d.auth.agent.create({
			ownerId: d.userId,
			name: "bot",
			type: "autonomous",
			permissions: [],
		});
		expect(await mcp.clients.agentFor(CLIENT_ID)).toBeNull();
		await mcp.clients.bindAgent(CLIENT_ID, agent.id);
		expect(s.calls).toEqual([CLIENT_ID]);
		expect(await mcp.clients.agentFor(CLIENT_ID)).toBe(agent.id);
		const tokens = await issueTokens(mcp, CLIENT_ID, d.userId);
		expect(decodePayload(tokens.access_token).agent_id).toBe(agent.id);
	});

	it("bindAgent refuses a URL whose document cannot be fetched", async () => {
		const d = await bootDb();
		const s = docs({});
		const mcp = createMcpModule({
			auth: d.auth,
			config: mcpConfig(cimdConfig(s.fetchImpl)),
			resolveUserId: async () => d.userId,
		});
		const agent = await d.auth.agent.create({
			ownerId: d.userId,
			name: "bot",
			type: "autonomous",
			permissions: [],
		});
		await expect(mcp.clients.bindAgent(CLIENT_ID, agent.id)).rejects.toThrow(/Unknown client/);
	});
});

describe("blocking a CIMD client through mcp.cimd", () => {
	async function boot() {
		const s = docs({
			[CLIENT_ID]: docFor(CLIENT_ID),
			[`https://app.${HOST}/m.json`]: docFor(`https://app.${HOST}/m.json`),
		});
		const d = await bootDb();
		const mcp = createMcpModule({
			auth: d.auth,
			config: { ...mcpConfig(cimdConfig(s.fetchImpl)), jtiDenylist: createInMemoryJtiDenylist() },
			resolveUserId: async () => d.userId,
		});
		return { d, s, mcp };
	}

	it("a URL block stops authorization, kills refresh tokens and denies live access tokens", async () => {
		const { d, mcp } = await boot();
		const tokens = await issueTokens(mcp, CLIENT_ID, d.userId);
		expect(tokens.refresh_token).toBeTruthy();
		expect(await mcp.validateToken(tokens.access_token)).toMatchObject({ success: true });

		const block = await mcp.cimd.block({ kind: "url", value: CLIENT_ID, reason: "abuse" });
		expect((await mcp.cimd.listBlocks()).map((b) => b.id)).toContain(block.id);

		const rows = await d.auth.db
			.select()
			.from(oauthAccessTokens)
			.where(eq(oauthAccessTokens.clientId, CLIENT_ID));
		expect(rows).toHaveLength(0);
		expect((await mcp.cimd.inspect(CLIENT_ID))?.disabledReason).toBe("blocked");

		const auth = await mcp.authorize(authorizeUrl(CLIENT_ID));
		expect(auth.success).toBe(false);
		expect(!auth.success && auth.error.code).toBe("INVALID_CLIENT");

		const refreshed = await mcp.token(
			tokenRequest({
				grant_type: "refresh_token",
				refresh_token: tokens.refresh_token ?? "",
				client_id: CLIENT_ID,
			}),
		);
		expect(refreshed.success).toBe(false);
		expect((await mcp.validateToken(tokens.access_token)).success).toBe(false);
		const described = await mcp.describeClient(CLIENT_ID);
		expect(described.success).toBe(false);
	});

	it("unblock plus enable restores the client", async () => {
		const { d, mcp } = await boot();
		await issueTokens(mcp, CLIENT_ID, d.userId);
		const block = await mcp.cimd.block({ kind: "url", value: CLIENT_ID });
		await mcp.cimd.unblock(block.id);
		expect((await mcp.authorize(authorizeUrl(CLIENT_ID))).success).toBe(false);
		await mcp.cimd.enable(CLIENT_ID);
		const again = await mcp.authorize(authorizeUrl(CLIENT_ID));
		expect(again.success && again.data.redirectUri.startsWith(CONSENT)).toBe(true);
	});

	it("a host block covers subdomains before any fetch", async () => {
		const { s, mcp } = await boot();
		await mcp.cimd.block({ kind: "host", value: "*.Client.Example.com." });
		const sub = `https://app.${HOST}/m.json`;
		const res = await mcp.authorize(authorizeUrl(sub));
		expect(res.success).toBe(false);
		expect(s.calls).toEqual([]);
	});

	it("refresh forces a fetch and refuses a blocked client", async () => {
		const { s, mcp } = await boot();
		await mcp.authorize(authorizeUrl(CLIENT_ID));
		const first = await mcp.cimd.refresh(CLIENT_ID);
		expect(first.success).toBe(true);
		expect(s.calls).toEqual([CLIENT_ID, CLIENT_ID]);
		await mcp.cimd.block({ kind: "url", value: CLIENT_ID });
		expect((await mcp.cimd.refresh(CLIENT_ID)).success).toBe(false);
	});

	it("rejects malformed host rules", async () => {
		const { mcp } = await boot();
		await expect(mcp.cimd.block({ kind: "host", value: "a.com/path" })).rejects.toThrow(
			/bare hostname/,
		);
	});
});
