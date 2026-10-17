/** Client ID Metadata Documents: private_key_jwt support, Cache-Control driven refresh and the failed-fetch negative cache. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cimdCacheSeconds } from "../src/mcp/client-metadata.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import type { Harness, KeyMaterial } from "./mcp-test-harness.js";
import {
	BASE_URL,
	CLIENT_ASSERTION_TYPE,
	clientAssertion,
	makeHarness,
	newKeys,
	REDIRECT,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const CLIENT_ID = "https://client.example.test/metadata.json";
const JWKS_URL = "https://client.example.test/jwks.json";

interface Served {
	body: unknown;
	status?: number;
	cacheControl?: string;
}

function server(routes: Record<string, Served>) {
	const calls: string[] = [];
	const fetchImpl = (async (url: string) => {
		calls.push(url);
		const route = routes[url];
		if (!route) return new Response("not found", { status: 404 });
		return new Response(JSON.stringify(route.body), {
			status: route.status ?? 200,
			headers: {
				"content-type": "application/json",
				...(route.cacheControl ? { "cache-control": route.cacheControl } : {}),
			},
		});
	}) as unknown as typeof fetch;
	return { calls, fetchImpl, routes };
}

function cimdHarness(
	routes: Record<string, Served>,
	extra: { negativeCacheSeconds?: number } = {},
): { h: Harness; calls: string[]; routes: Record<string, Served> } {
	const s = server(routes);
	const h = makeHarness({
		clientIdMetadataDocuments: {
			enabled: true,
			resolver: async () => ["93.184.216.34"],
			fetchImpl: s.fetchImpl,
			...extra,
		},
	});
	return { h, calls: s.calls, routes: s.routes };
}

function doc(extra: Record<string, unknown> = {}): Record<string, unknown> {
	return { client_id: CLIENT_ID, redirect_uris: [REDIRECT], client_name: "CIMD", ...extra };
}

async function authorize(h: Harness) {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const params: Record<string, string> = {
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT,
		scope: "mcp:read",
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
	};
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
	return { res: await h.mcp.authorize(new Request(url)), verifier };
}

describe("cimdCacheSeconds", () => {
	it("clamps max-age to 60s..24h and defaults to 1h", () => {
		expect(cimdCacheSeconds(undefined)).toBe(3600);
		expect(cimdCacheSeconds("public")).toBe(3600);
		expect(cimdCacheSeconds("max-age=5")).toBe(60);
		expect(cimdCacheSeconds("public, max-age=300")).toBe(300);
		expect(cimdCacheSeconds("max-age=999999999")).toBe(86400);
		expect(cimdCacheSeconds("no-store")).toBe(60);
		expect(cimdCacheSeconds("max-age=-5")).toBe(3600);
	});
});

describe("CIMD private_key_jwt", () => {
	async function codeExchange(h: Harness, assertion: string) {
		const { res, verifier } = await authorize(h);
		if (!res.success) throw new Error(res.error.message);
		const code = new URL(res.data.redirectUri).searchParams.get("code") ?? "";
		return h.mcp.token(
			tokenRequest({
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				code_verifier: verifier,
				resource: RESOURCE,
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: assertion,
			}),
		);
	}

	it("accepts inline jwks and authenticates with a signed assertion", async () => {
		const keys = await newKeys();
		const { h } = cimdHarness({
			[CLIENT_ID]: {
				body: doc({
					token_endpoint_auth_method: "private_key_jwt",
					jwks: { keys: [keys.jwk] },
					some_unknown_field: { nested: true },
				}),
			},
		});
		const res = await codeExchange(h, await clientAssertion(keys, CLIENT_ID));
		expect(res.success).toBe(true);
	});

	it("accepts jwks_uri and fetches the keys", async () => {
		const keys = await newKeys();
		const { h, calls } = cimdHarness({
			[CLIENT_ID]: {
				body: doc({ token_endpoint_auth_method: "private_key_jwt", jwks_uri: JWKS_URL }),
			},
			[JWKS_URL]: { body: { keys: [keys.jwk] } },
		});
		const res = await codeExchange(h, await clientAssertion(keys, CLIENT_ID));
		expect(res.success).toBe(true);
		expect(calls).toContain(JWKS_URL);
	});

	it("rejects an assertion signed by a key outside the document", async () => {
		const keys = await newKeys();
		const other = await newKeys();
		const { h } = cimdHarness({
			[CLIENT_ID]: {
				body: doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [keys.jwk] } }),
			},
		});
		const res = await codeExchange(h, await clientAssertion(other, CLIENT_ID));
		expect(res.success).toBe(false);
	});

	it("still rejects shared-secret methods and malformed key material", async () => {
		const keys: KeyMaterial = await newKeys();
		const bad: Array<Record<string, unknown>> = [
			{ token_endpoint_auth_method: "client_secret_basic" },
			{ token_endpoint_auth_method: "client_secret_post" },
			{ token_endpoint_auth_method: "private_key_jwt" },
			{
				token_endpoint_auth_method: "private_key_jwt",
				jwks: { keys: [keys.jwk] },
				jwks_uri: JWKS_URL,
			},
			{ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [{ ...keys.jwk, d: "x" }] } },
			{ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "http://client.example.test/j" },
			{
				token_endpoint_auth_method: "private_key_jwt",
				jwks: { keys: [keys.jwk] },
				client_secret: "x",
			},
		];
		for (const extra of bad) {
			const { h } = cimdHarness({ [CLIENT_ID]: { body: doc(extra) } });
			const { res } = await authorize(h);
			expect(res.success).toBe(false);
		}
	});
});

describe("CIMD caching", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-10-12T00:00:00Z"));
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	const advance = (seconds: number) => vi.setSystemTime(Date.now() + seconds * 1000);
	const fetchesOf = (calls: string[]) => calls.filter((c) => c === CLIENT_ID).length;

	it("re-reads the document after its max-age, not before", async () => {
		const { h, calls } = cimdHarness({
			[CLIENT_ID]: { body: doc(), cacheControl: "max-age=300" },
		});
		expect((await authorize(h)).res.success).toBe(true);
		expect(fetchesOf(calls)).toBe(1);
		advance(200);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(1);
		advance(120);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(2);
	});

	it("never re-reads sooner than 60 seconds, whatever max-age says", async () => {
		const { h, calls } = cimdHarness({
			[CLIENT_ID]: { body: doc(), cacheControl: "max-age=1" },
		});
		await authorize(h);
		advance(30);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(1);
		advance(31);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(2);
	});

	it("keeps the one hour default without Cache-Control", async () => {
		const { h, calls } = cimdHarness({ [CLIENT_ID]: { body: doc() } });
		await authorize(h);
		advance(3000);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(1);
		advance(700);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(2);
	});

	it("remembers a failed fetch briefly, then retries", async () => {
		const { h, calls, routes } = cimdHarness({ [CLIENT_ID]: { body: {}, status: 500 } });
		expect((await authorize(h)).res.success).toBe(false);
		expect((await authorize(h)).res.success).toBe(false);
		expect(fetchesOf(calls)).toBe(1);
		routes[CLIENT_ID] = { body: doc() };
		advance(31);
		expect((await authorize(h)).res.success).toBe(true);
		expect(fetchesOf(calls)).toBe(2);
	});

	it("can turn the negative cache off", async () => {
		const { h, calls } = cimdHarness(
			{ [CLIENT_ID]: { body: {}, status: 500 } },
			{ negativeCacheSeconds: 0 },
		);
		await authorize(h);
		await authorize(h);
		expect(fetchesOf(calls)).toBe(2);
	});

	it("fails closed when a refresh fails for a stored document", async () => {
		const { h, routes } = cimdHarness({ [CLIENT_ID]: { body: doc(), cacheControl: "max-age=60" } });
		expect((await authorize(h)).res.success).toBe(true);
		routes[CLIENT_ID] = { body: {}, status: 500 };
		advance(61);
		expect((await authorize(h)).res.success).toBe(false);
	});
});
