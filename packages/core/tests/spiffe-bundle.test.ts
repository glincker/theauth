import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseSpiffeBundle } from "../src/device/spiffe/bundle.js";
import { createBundleStore } from "../src/device/spiffe/bundle-store.js";
import { verifyX509Svid } from "../src/device/spiffe/x509-svid.js";
import type { TestPki } from "./spiffe-fixtures.js";
import { b64, bundleDoc, jwtKey, makePki } from "./spiffe-fixtures.js";

let pki: TestPki;
let rootB: ReturnType<TestPki["otherRoot"]>;
beforeAll(() => {
	pki = makePki();
	rootB = pki.otherRoot("rootb", "spiffe://example.org");
});
afterAll(() => pki.cleanup());

const URL_ = "https://spire.example/bundle";

function endpoint(responses: Array<() => Response | Promise<Response>>) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	let i = 0;
	const fetchFn = (async (url: string, init?: RequestInit) => {
		calls.push({ url, init });
		const next = responses[Math.min(i++, responses.length - 1)] as () =>
			| Response
			| Promise<Response>;
		return next();
	}) as unknown as typeof fetch;
	return { fetchFn, calls };
}
const json = (doc: unknown, init?: ResponseInit) => () =>
	new Response(JSON.stringify(doc), { status: 200, ...init });

describe("bundle parsing (Trust Domain and Bundle section 4)", () => {
	it("reads x509-svid and jwt-svid keys, the sequence and the refresh hint", async () => {
		const k = await jwtKey("ES256", "a");
		const r = parseSpiffeBundle(
			"example.org",
			bundleDoc({
				cas: [pki.ca.der],
				jwt: [{ kid: "a", jwk: k.publicJwk }],
				sequence: 7,
				refreshHint: 120,
			}),
		);
		expect(r.ok).toBe(true);
		if (!r.ok) return;
		expect(r.bundle).toMatchObject({ sequence: 7, refreshHintSeconds: 120 });
		expect(r.bundle.x509Authorities).toHaveLength(1);
		expect(r.bundle.jwtAuthorities.has("a")).toBe(true);
	});

	it("ignores unknown use and kty, a non CA x509 entry, and a jwt key with private members or no kid", async () => {
		const leaf = pki.leaf();
		const k = await jwtKey("ES256", "a");
		const r = parseSpiffeBundle(
			"example.org",
			bundleDoc({
				cas: [pki.ca.der],
				extra: [
					{ kty: "EC", use: "wit-svid", kid: "w" },
					{ kty: "oct", use: "jwt-svid", kid: "o", k: "AAAA" },
					{ kty: "EC", use: "x509-svid", x5c: [b64(leaf.der)] },
					{ ...k.publicJwk, use: "jwt-svid" },
					{ kty: "EC", x5c: [b64(pki.ca.der)] },
				],
			}),
		);
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.bundle.x509Authorities).toHaveLength(1);
			expect(r.bundle.jwtAuthorities.size).toBe(0);
			expect(r.skipped).toBe(3);
		}
	});

	it("refuses a bundle with keys but no usable authority, and non JWK Set input", () => {
		expect(
			parseSpiffeBundle(
				"example.org",
				bundleDoc({ extra: [{ kty: "EC", use: "x509-svid", x5c: ["AAAA"] }] }),
			).ok,
		).toBe(false);
		expect(parseSpiffeBundle("example.org", "not json").ok).toBe(false);
		expect(parseSpiffeBundle("example.org", { nokeys: true }).ok).toBe(false);
		expect(parseSpiffeBundle("example.org", { keys: [], spiffe_sequence: -1 }).ok).toBe(false);
	});
});

describe("bundle store", () => {
	it("refuses bad configuration at startup", () => {
		expect(() => createBundleStore({ "Bad Name": { roots: [pki.ca.pem] } })).toThrow(
			/valid trust domain/,
		);
		expect(() => createBundleStore({ "example.org": {} })).toThrow(/needs a bundle/);
		expect(() =>
			createBundleStore({ "example.org": { endpoint: { url: "http://spire.example/b" } } }),
		).toThrow(/https/);
		expect(() =>
			createBundleStore({
				"example.org": { roots: [rootB.pem] },
				"spiffe://example.org": { roots: [pki.ca.pem] },
			}),
		).toThrow(/twice/);
		expect(() => createBundleStore({ "example.org": { roots: [pki.leaf().pem] } })).toThrow(/CA/);
	});

	it("accepts PEM roots, alone or with a bundle", async () => {
		const store = createBundleStore({ "example.org": { roots: [pki.ca.pem] } });
		expect((await store.get("example.org"))?.x509Authorities).toHaveLength(1);
		const both = createBundleStore({
			"example.org": { bundle: bundleDoc({ cas: [pki.ca.der] }), roots: [rootB.pem] },
		});
		expect((await both.get("example.org"))?.x509Authorities).toHaveLength(2);
		expect(await both.get("unknown.example")).toBeNull();
	});

	it("rotates: a refresh after the hint picks up a new authority and still honors the old one it keeps", async () => {
		let t = 1_000_000;
		const first = bundleDoc({ cas: [pki.ca.der], sequence: 1, refreshHint: 600 });
		const second = bundleDoc({ cas: [pki.ca.der, rootB.der], sequence: 2, refreshHint: 600 });
		const { fetchFn, calls } = endpoint([json(first), json(second)]);
		const store = createBundleStore(
			{ "example.org": { endpoint: { url: URL_, fetch: fetchFn } } },
			() => t,
		);

		expect((await store.get("example.org"))?.x509Authorities).toHaveLength(1);
		expect(calls[0]).toMatchObject({ url: URL_, init: { redirect: "error", method: "GET" } });
		t += 599_000;
		await store.get("example.org");
		expect(calls).toHaveLength(1);
		t += 2000;
		expect((await store.get("example.org"))?.x509Authorities).toHaveLength(2);
		expect(calls).toHaveLength(2);

		// An SVID from the newly published root verifies only after the rotation.
		const leaf = pki.leaf({ signer: rootB });
		const r = await verifyX509Svid([leaf.der], store, { now: new Date() });
		expect(r.ok).toBe(true);
	});

	it("never polls faster than minRefreshSeconds, whatever the hint says", async () => {
		let t = 0;
		const { fetchFn, calls } = endpoint([json(bundleDoc({ cas: [pki.ca.der], refreshHint: 1 }))]);
		const store = createBundleStore(
			{ "example.org": { endpoint: { url: URL_, fetch: fetchFn, minRefreshSeconds: 60 } } },
			() => t,
		);
		await store.get("example.org");
		t += 30_000;
		await store.get("example.org");
		expect(calls).toHaveLength(1);
		t += 31_000;
		await store.get("example.org");
		expect(calls).toHaveLength(2);
	});

	it("refuses a sequence that goes backwards or disappears, and keeps the last good bundle", async () => {
		let t = 0;
		const { fetchFn } = endpoint([
			json(bundleDoc({ cas: [pki.ca.der], sequence: 5, refreshHint: 60 })),
			json(bundleDoc({ cas: [rootB.der], sequence: 4 })),
			json(bundleDoc({ cas: [rootB.der] })),
		]);
		const store = createBundleStore(
			{ "example.org": { endpoint: { url: URL_, fetch: fetchFn } } },
			() => t,
		);
		expect((await store.get("example.org"))?.sequence).toBe(5);
		t += 61_000;
		expect(await store.refresh("example.org")).toMatchObject({
			ok: false,
			reason: expect.stringContaining("backwards"),
		});
		expect(await store.refresh("example.org")).toMatchObject({ ok: false });
		expect((await store.get("example.org"))?.x509Authorities[0]?.der).toEqual(pki.ca.der);
	});

	it("keeps the last good bundle through failures, then fails closed after maxStaleSeconds", async () => {
		let t = 0;
		const { fetchFn } = endpoint([
			json(bundleDoc({ cas: [pki.ca.der], refreshHint: 60 })),
			() => new Response("boom", { status: 500 }),
		]);
		const store = createBundleStore(
			{ "example.org": { endpoint: { url: URL_, fetch: fetchFn, maxStaleSeconds: 3600 } } },
			() => t,
		);
		expect(await store.get("example.org")).not.toBeNull();
		t += 120_000;
		expect(await store.get("example.org")).not.toBeNull();
		t += 3_500_000;
		expect(await store.get("example.org")).toBeNull();
	});

	it("fails closed when the first fetch fails, and on network errors, big bodies and bad JSON", async () => {
		const mk = (fetchFn: typeof fetch, extra = {}) =>
			createBundleStore({ "example.org": { endpoint: { url: URL_, fetch: fetchFn, ...extra } } });
		expect(
			await mk((async () => {
				throw new Error("net");
			}) as unknown as typeof fetch).get("example.org"),
		).toBeNull();
		expect(
			await mk(endpoint([() => new Response("{not json")]).fetchFn).get("example.org"),
		).toBeNull();
		const big = endpoint([() => new Response(JSON.stringify(bundleDoc({ cas: [pki.ca.der] })))]);
		expect(await mk(big.fetchFn, { maxBytes: 50 }).get("example.org")).toBeNull();
		const declared = endpoint([
			() => new Response("{}", { headers: { "content-length": "99999999" } }),
		]);
		expect(await mk(declared.fetchFn).get("example.org")).toBeNull();
	});

	it("an empty keys array revokes every authority of the trust domain", async () => {
		let t = 0;
		const { fetchFn } = endpoint([
			json(bundleDoc({ cas: [pki.ca.der], sequence: 1, refreshHint: 60 })),
			json({ keys: [], spiffe_sequence: 2 }),
		]);
		const store = createBundleStore(
			{ "example.org": { endpoint: { url: URL_, fetch: fetchFn } } },
			() => t,
		);
		const leaf = pki.leaf();
		expect((await verifyX509Svid([leaf.der], store, { now: new Date() })).ok).toBe(true);
		t += 61_000;
		expect(await verifyX509Svid([leaf.der], store, { now: new Date() })).toMatchObject({
			ok: false,
			code: "untrusted_chain",
		});
	});

	it("shares one request between concurrent refreshes", async () => {
		const { fetchFn, calls } = endpoint([
			async () => {
				await new Promise((r) => setTimeout(r, 20));
				return json(bundleDoc({ cas: [pki.ca.der] }))();
			},
		]);
		const store = createBundleStore({ "example.org": { endpoint: { url: URL_, fetch: fetchFn } } });
		await Promise.all([
			store.get("example.org"),
			store.get("example.org"),
			store.get("example.org"),
		]);
		expect(calls).toHaveLength(1);
	});
});
