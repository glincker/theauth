import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { x509Thumbprint } from "../src/device/credentials.js";
import { createBundleStore } from "../src/device/spiffe/bundle-store.js";
import { verifyJwtSvid } from "../src/device/spiffe/jwt-svid.js";
import { certThumbprint, verifyX509Svid } from "../src/device/spiffe/x509-svid.js";
import type { JwtKey, TestPki } from "./spiffe-fixtures.js";
import { bundleDoc, jwtKey, jwtSvid, LEAF_OK, makePki, replaceExt } from "./spiffe-fixtures.js";

const ID = "spiffe://example.org/ns/prod/sa/robot";
let pki: TestPki;
let store: ReturnType<typeof createBundleStore>;
const now = () => new Date();

beforeAll(() => {
	pki = makePki();
	store = createBundleStore({ "example.org": { bundle: bundleDoc({ cas: [pki.ca.der] }) } });
});
afterAll(() => pki.cleanup());

async function check(
	chain: Uint8Array[],
	extra: Partial<Parameters<typeof verifyX509Svid>[2]> = {},
) {
	return verifyX509Svid(chain, store, { now: now(), ...extra });
}

describe("X.509-SVID (X509-SVID.md)", () => {
	it("accepts a valid leaf, reports the id and the RFC 8705 thumbprint", async () => {
		const leaf = pki.leaf();
		const r = await check([leaf.der]);
		expect(r.ok).toBe(true);
		if (!r.ok) return;
		expect(r.identity.spiffeId).toBe(ID);
		expect(r.identity.trustDomain).toBe("example.org");
		expect(r.identity.thumbprint).toBe(await x509Thumbprint(leaf.der));
		expect(r.identity.thumbprint).toBe(await certThumbprint(leaf.der));
	});

	it("accepts an RSA leaf signed by an EC root, and a chain through an intermediate", async () => {
		expect((await check([pki.leaf({ key: "rsa" }).der])).ok).toBe(true);
		const int = pki.intermediate();
		const leaf = pki.leaf({ signer: int });
		expect((await check([leaf.der, int.der])).ok).toBe(true);
	});

	it("refuses a chain that skips the intermediate", async () => {
		const int = pki.intermediate();
		const leaf = pki.leaf({ signer: int });
		const r = await check([leaf.der]);
		expect(r).toMatchObject({ ok: false, code: "untrusted_chain" });
	});

	it("refuses a missing URI SAN", async () => {
		const ext = replaceExt(LEAF_OK, "subjectAltName", "subjectAltName=DNS:robot.example.org");
		expect(await check([pki.leaf({ ext }).der])).toMatchObject({ ok: false, code: "no_uri_san" });
		const none = replaceExt(LEAF_OK, "subjectAltName", null);
		expect(await check([pki.leaf({ ext: none }).der])).toMatchObject({
			ok: false,
			code: "no_uri_san",
		});
	});

	it("refuses more than one URI SAN, even with a valid first one", async () => {
		const ext = replaceExt(
			LEAF_OK,
			"subjectAltName",
			`subjectAltName=critical,URI:${ID},URI:spiffe://example.org/other`,
		);
		expect(await check([pki.leaf({ ext }).der])).toMatchObject({
			ok: false,
			code: "multiple_uri_sans",
		});
	});

	it("allows a DNS SAN next to the one URI SAN (section 2)", async () => {
		const ext = replaceExt(
			LEAF_OK,
			"subjectAltName",
			`subjectAltName=critical,URI:${ID},DNS:robot.example.org`,
		);
		expect((await check([pki.leaf({ ext }).der])).ok).toBe(true);
	});

	it("refuses a URI SAN that is not a valid SPIFFE ID or has no path", async () => {
		for (const uri of [
			"https://example.org/a",
			"spiffe://example.org",
			"spiffe://example.org/a/",
			"spiffe://Example.org/a",
		]) {
			const ext = replaceExt(LEAF_OK, "subjectAltName", `subjectAltName=critical,URI:${uri}`);
			expect(await check([pki.leaf({ ext }).der]), uri).toMatchObject({
				ok: false,
				code: "invalid_spiffe_id",
			});
		}
	});

	it("refuses a wrong trust domain and a trust domain signed by another root", async () => {
		const foreign = replaceExt(
			LEAF_OK,
			"subjectAltName",
			"subjectAltName=critical,URI:spiffe://other.example/ns/a",
		);
		expect(await check([pki.leaf({ ext: foreign }).der])).toMatchObject({
			ok: false,
			code: "untrusted_domain",
		});
		// The right trust domain name, but signed by a root that is not in the bundle.
		const rogue = pki.otherRoot("rogue", "spiffe://example.org");
		const r = await check([pki.leaf({ signer: rogue }).der]);
		expect(r).toMatchObject({ ok: false, code: "untrusted_chain" });
	});

	it("a CA of trust domain A cannot mint ids of trust domain B", async () => {
		const rootB = pki.otherRoot("rootb", "spiffe://b.example");
		const both = createBundleStore({
			"example.org": { bundle: bundleDoc({ cas: [pki.ca.der] }) },
			"b.example": { bundle: bundleDoc({ cas: [rootB.der] }) },
		});
		const fromA = pki.leaf({
			ext: replaceExt(
				LEAF_OK,
				"subjectAltName",
				"subjectAltName=critical,URI:spiffe://b.example/x",
			),
		});
		const r = await verifyX509Svid([fromA.der], both, { now: now() });
		expect(r).toMatchObject({ ok: false, code: "untrusted_chain" });
	});

	it("refuses expired and not yet valid SVIDs, honoring the clock skew", async () => {
		const leaf = pki.leaf({ days: 1 });
		const day = 86_400_000;
		expect(await check([leaf.der], { now: new Date(Date.now() + 2 * day) })).toMatchObject({
			ok: false,
			code: "expired",
		});
		expect(await check([leaf.der], { now: new Date(Date.now() - day) })).toMatchObject({
			ok: false,
			code: "not_yet_valid",
		});
		expect((await check([leaf.der], { now: new Date(Date.now() + day + 10_000) })).ok).toBe(true);
		expect(
			await check([leaf.der], { now: new Date(Date.now() + day + 10_000), clockSkewSeconds: 0 }),
		).toMatchObject({ ok: false, code: "expired" });
	});

	it("refuses a leaf with the CA flag set, even with keyCertSign", async () => {
		const ca = replaceExt(LEAF_OK, "basicConstraints", "basicConstraints=critical,CA:TRUE");
		expect(await check([pki.leaf({ ext: ca }).der])).toMatchObject({ ok: false, code: "ca_leaf" });
		const both = replaceExt(ca, "keyUsage", "keyUsage=critical,digitalSignature,keyCertSign");
		expect(await check([pki.leaf({ ext: both }).der])).toMatchObject({
			ok: false,
			code: "ca_leaf",
		});
	});

	it("never accepts a signing certificate as a leaf", async () => {
		const int = pki.intermediate({
			ext: [
				"basicConstraints=critical,CA:TRUE",
				"keyUsage=critical,keyCertSign",
				`subjectAltName=URI:spiffe://example.org/signer`,
			],
		});
		expect((await check([int.der])).ok).toBe(false);
	});

	it("enforces key usage: present, critical, digitalSignature, no keyCertSign or cRLSign", async () => {
		const cases: Array<[string, string | null]> = [
			["missing", null],
			["not critical", "keyUsage=digitalSignature"],
			["no digitalSignature", "keyUsage=critical,keyEncipherment"],
			["keyCertSign", "keyUsage=critical,digitalSignature,keyCertSign"],
			["cRLSign", "keyUsage=critical,digitalSignature,cRLSign"],
		];
		for (const [name, line] of cases) {
			const r = await check([pki.leaf({ ext: replaceExt(LEAF_OK, "keyUsage", line) }).der]);
			expect(r, name).toMatchObject({ ok: false, code: "key_usage" });
		}
		const fine = replaceExt(
			LEAF_OK,
			"keyUsage",
			"keyUsage=critical,digitalSignature,keyEncipherment,keyAgreement",
		);
		expect((await check([pki.leaf({ ext: fine }).der])).ok).toBe(true);
	});

	it("refuses extended key usage without clientAuth, and an unknown critical extension", async () => {
		const server = replaceExt(LEAF_OK, "extendedKeyUsage", "extendedKeyUsage=serverAuth");
		expect(await check([pki.leaf({ ext: server }).der])).toMatchObject({
			ok: false,
			code: "key_usage",
		});
		const unknown = [...LEAF_OK, "1.3.6.1.4.1.99999.1=critical,ASN1:UTF8String:x"];
		expect(await check([pki.leaf({ ext: unknown }).der])).toMatchObject({
			ok: false,
			code: "extension",
		});
	});

	it("requires a critical SAN when the Subject is empty (section 3.1)", async () => {
		const ext = replaceExt(LEAF_OK, "subjectAltName", `subjectAltName=URI:${ID}`);
		expect(await check([pki.leaf({ ext }).der])).toMatchObject({ ok: false, code: "extension" });
	});

	it("applies maxLifetimeSeconds and rejects garbage", async () => {
		const leaf = pki.leaf({ days: 2 });
		expect(await check([leaf.der], { maxLifetimeSeconds: 3600 })).toMatchObject({
			ok: false,
			code: "lifetime_too_long",
		});
		expect(await check([new Uint8Array([1, 2, 3])])).toMatchObject({
			ok: false,
			code: "malformed",
		});
		expect(await check([])).toMatchObject({ ok: false, code: "malformed" });
		expect(await check(Array(7).fill(leaf.der))).toMatchObject({ ok: false, code: "malformed" });
	});

	it("refuses a leaf whose intermediate is not a CA or is expired", async () => {
		const notCa = pki.intermediate({
			ext: ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature"],
		});
		const leaf = pki.leaf({ signer: notCa });
		expect((await check([leaf.der, notCa.der])).ok).toBe(false);
		const short = pki.intermediate({ days: 1 });
		const leaf2 = pki.leaf({ signer: short, days: 30 });
		expect((await check([leaf2.der, short.der])).ok).toBe(true);
		const later = new Date(Date.now() + 10 * 86_400_000);
		expect(await check([leaf2.der, short.der], { now: later })).toMatchObject({
			ok: false,
			code: "untrusted_chain",
		});
	});

	it("enforces pathLenConstraint of the root path", async () => {
		const int1 = pki.intermediate({
			ext: ["basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign"],
		});
		const leaf = pki.leaf({ signer: int1 });
		expect((await check([leaf.der, int1.der])).ok).toBe(true);
	});
});

describe("JWT-SVID (JWT-SVID.md)", () => {
	const aud = "https://theauth.example/api";
	let es: JwtKey;
	let jwtStore: ReturnType<typeof createBundleStore>;
	beforeAll(async () => {
		es = await jwtKey("ES256", "k1");
		jwtStore = createBundleStore({
			"example.org": { bundle: bundleDoc({ jwt: [{ kid: es.kid, jwk: es.publicJwk }] }) },
		});
	});
	const run = (token: string, extra: Partial<Parameters<typeof verifyJwtSvid>[2]> = {}) =>
		verifyJwtSvid(token, jwtStore, { audience: [aud], now: new Date(), ...extra });

	it("accepts a valid token with ES256, RS256 and PS256", async () => {
		const ok = await run(await jwtSvid(es, { sub: ID, aud }));
		expect(ok).toMatchObject({
			ok: true,
			identity: { spiffeId: ID, trustDomain: "example.org", kid: "k1" },
		});
		for (const alg of ["RS256", "PS256"] as const) {
			const k = await jwtKey(alg, `k-${alg}`);
			const s = createBundleStore({
				"example.org": { bundle: bundleDoc({ jwt: [{ kid: k.kid, jwk: k.publicJwk }] }) },
			});
			const r = await verifyJwtSvid(await jwtSvid(k, { sub: ID, aud }), s, {
				audience: [aud],
				now: new Date(),
			});
			expect(r.ok, alg).toBe(true);
		}
	});

	it("accepts an aud array that contains our audience", async () => {
		expect((await run(await jwtSvid(es, { sub: ID, aud: ["other", aud] }))).ok).toBe(true);
	});

	it("refuses a wrong or missing audience", async () => {
		expect(await run(await jwtSvid(es, { sub: ID, aud: "https://other" }))).toMatchObject({
			ok: false,
			code: "wrong_audience",
		});
		expect(await run(await jwtSvid(es, { sub: ID }))).toMatchObject({
			ok: false,
			code: "missing_claim",
		});
		expect(await run(await jwtSvid(es, { sub: ID, aud }), { audience: [] })).toMatchObject({
			ok: false,
			code: "wrong_audience",
		});
	});

	it("refuses expired, missing exp, not yet valid and long lived tokens", async () => {
		const t = Math.floor(Date.now() / 1000);
		expect(await run(await jwtSvid(es, { sub: ID, aud, exp: t - 120 }))).toMatchObject({
			ok: false,
			code: "expired",
		});
		expect(await run(await jwtSvid(es, { sub: ID, aud, exp: null }))).toMatchObject({
			ok: false,
			code: "missing_claim",
		});
		expect(await run(await jwtSvid(es, { sub: ID, aud, nbf: t + 600 }))).toMatchObject({
			ok: false,
			code: "not_yet_valid",
		});
		expect(await run(await jwtSvid(es, { sub: ID, aud, exp: t + 86_400 }))).toMatchObject({
			ok: false,
			code: "lifetime_too_long",
		});
		expect(
			await run(await jwtSvid(es, { sub: ID, aud, exp: t + 86_400 }), { maxTtlSeconds: 90_000 }),
		).toMatchObject({ ok: true });
		expect(
			await run(await jwtSvid(es, { sub: ID, aud, iat: t - 7200, exp: t + 60 })),
		).toMatchObject({ ok: false, code: "lifetime_too_long" });
	});

	it("refuses a bad signature, unknown kid, other algorithms, extra headers and bad typ", async () => {
		const other = await jwtKey("ES256", "k1");
		expect(await run(await jwtSvid(other, { sub: ID, aud }))).toMatchObject({
			ok: false,
			code: "bad_signature",
		});
		expect(await run(await jwtSvid({ ...es, kid: "nope" }, { sub: ID, aud }))).toMatchObject({
			ok: false,
			code: "untrusted_chain",
		});
		const ed = await jwtKey("EdDSA", "k1");
		expect(await run(await jwtSvid(ed, { sub: ID, aud }))).toMatchObject({
			ok: false,
			code: "unsupported_alg",
		});
		expect(await run(await jwtSvid(es, { sub: ID, aud }, { x5u: "https://evil" }))).toMatchObject({
			ok: false,
			code: "malformed",
		});
		expect(await run(await jwtSvid(es, { sub: ID, aud }, { typ: "at+jwt" }))).toMatchObject({
			ok: false,
			code: "malformed",
		});
		expect((await run(await jwtSvid(es, { sub: ID, aud }, { typ: "JOSE" }))).ok).toBe(true);
	});

	it("refuses alg none and a token that is not a compact JWS", async () => {
		const none = `${btoa(JSON.stringify({ alg: "none", kid: "k1" })).replace(/=/g, "")}.${btoa(JSON.stringify({ sub: ID, aud, exp: Math.floor(Date.now() / 1000) + 60 })).replace(/=/g, "")}.`;
		expect((await run(none)).ok).toBe(false);
		expect(await run("a.b")).toMatchObject({ ok: false, code: "malformed" });
	});

	it("refuses a sub that is not a SPIFFE ID, or is in a trust domain without a bundle", async () => {
		expect(await run(await jwtSvid(es, { sub: "robot", aud }))).toMatchObject({
			ok: false,
			code: "invalid_spiffe_id",
		});
		expect(await run(await jwtSvid(es, { sub: "spiffe://other.example/a", aud }))).toMatchObject({
			ok: false,
			code: "untrusted_domain",
		});
		expect(await run(await jwtSvid(es, { aud }))).toMatchObject({
			ok: false,
			code: "missing_claim",
		});
	});
});
