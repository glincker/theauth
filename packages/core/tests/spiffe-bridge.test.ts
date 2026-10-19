import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createSpiffeBridge } from "../src/device/spiffe/bridge.js";
import { createTheAuthHandler } from "../src/http/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import { AUTHORIZE_URL, CALL, codeOf, PERMS } from "./agent-dpop-helpers.js";
import { seedUser } from "./http/helpers.js";
import type { JwtKey, TestPki } from "./spiffe-fixtures.js";
import { bundleDoc, jwtKey, jwtSvid, LEAF_OK, makePki, replaceExt } from "./spiffe-fixtures.js";

const ROBOT = "spiffe://example.org/ns/prod/sa/robot";
const WORKER = "spiffe://example.org/ns/prod/sa/worker";
const AUD = "https://theauth.example";
let pki: TestPki;
let auth: TheAuth;
let es: JwtKey;
const X5T = "x5t#S256";

function leafFor(id: string, ext = LEAF_OK) {
	return pki.leaf({ ext: replaceExt(ext, "subjectAltName", `subjectAltName=critical,URI:${id}`) });
}

beforeAll(async () => {
	pki = makePki();
	es = await jwtKey("ES256", "k1");
	auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 1000,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
			confirmation: { methods: { [X5T]: (r) => r.headers.get("x-client-cert-sha256") } },
		},
		devices: {},
		auth: { session: { secret: "test-session-secret-that-is-at-least-32-chars!!" } },
	});
	await seedUser(auth, "alice");
});
afterAll(() => pki.cleanup());

function bridgeFor(agentMap: Record<string, string> = {}) {
	return createSpiffeBridge({
		trustDomains: {
			"example.org": {
				bundle: bundleDoc({ cas: [pki.ca.der], jwt: [{ kid: es.kid, jwk: es.publicJwk }] }),
			},
		},
		audience: [AUD],
		...(auth.device && { devices: auth.device }),
		agents: {
			get: (id) => auth.agent.get(id),
			rotate: (id, o) => auth.agent.rotate(id, o),
			map: agentMap,
		},
	});
}

describe("device principal", () => {
	it("maps an X.509-SVID to a device and returns the RFC 8705 cnf", async () => {
		const { device } = (await auth.device?.register({
			ownerId: "alice",
			name: "robot",
			permissions: PERMS,
			credential: { kind: "spiffe", spiffeId: ROBOT },
		})) as never;
		const leaf = leafFor(ROBOT);
		const r = await bridgeFor().authenticate({ kind: "x509", chain: leaf.pem });
		expect(r.ok).toBe(true);
		if (!r.ok) return;
		expect(r.principal).toMatchObject({ type: "device", device: { id: device.id } });
		expect(r.cnf?.[X5T]).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(r.svid.kind).toBe("x509");
		// The device then acts through the normal pipeline.
		const allowed = await auth.device?.authorize(device.id, CALL);
		expect(allowed?.allowed).toBe(true);
	});

	it("maps a JWT-SVID to the same device, with no cnf and no token", async () => {
		const r = await bridgeFor().authenticate({
			kind: "jwt",
			token: await jwtSvid(es, { sub: ROBOT, aud: AUD }),
		});
		expect(r).toMatchObject({ ok: true, principal: { type: "device" }, svid: { kind: "jwt" } });
		if (r.ok) expect(r.cnf).toBeUndefined();
	});

	it("refuses an SVID of an unmapped workload", async () => {
		const r = await bridgeFor().authenticate({
			kind: "x509",
			chain: leafFor("spiffe://example.org/ns/prod/sa/stranger").pem,
		});
		expect(r).toMatchObject({ ok: false, code: "unknown_workload" });
	});

	it("stops working when the device is suspended, revoked, or the mapping is revoked", async () => {
		const spiffeId = "spiffe://example.org/ns/prod/sa/lifecycle";
		const { device } = (await auth.device?.register({
			ownerId: "alice",
			name: "life",
			credential: { kind: "spiffe", spiffeId },
		})) as never;
		const bridge = bridgeFor();
		const present = () => bridge.authenticate({ kind: "x509", chain: leafFor(spiffeId).pem });
		expect((await present()).ok).toBe(true);
		await auth.device?.suspend(device.id);
		expect(await present()).toMatchObject({ ok: false, code: "unknown_workload" });
		await auth.device?.resume(device.id);
		expect((await present()).ok).toBe(true);
		await auth.device?.revoke(device.id);
		expect(await present()).toMatchObject({ ok: false, code: "unknown_workload" });
	});

	it("stops working when the SPIFFE credential is revoked", async () => {
		const spiffeId = "spiffe://example.org/ns/prod/sa/credrevoke";
		const { device, credential } = (await auth.device?.register({
			ownerId: "alice",
			name: "cr",
			credential: { kind: "spiffe", spiffeId },
		})) as never;
		const present = () => bridgeFor().authenticate({ kind: "x509", chain: leafFor(spiffeId).pem });
		expect((await present()).ok).toBe(true);
		await auth.device?.revokeCredential(device.id, credential.id);
		expect(await present()).toMatchObject({ ok: false, code: "unknown_workload" });
	});

	it("never lets enrollment claim a SPIFFE ID, and refuses a SPIFFE ID without a path or one that is taken", async () => {
		const token = (await auth.device?.createEnrollmentToken({
			ownerId: "alice",
			kind: "bulk",
			maxUses: 5,
		})) as never as { token: string };
		await expect(
			auth.device?.enroll({
				token: token.token,
				name: "x",
				credential: { kind: "spiffe", spiffeId: "spiffe://example.org/ns/a" },
			}),
		).rejects.toThrow(/cannot be claimed/);
		await expect(
			auth.device?.register({
				ownerId: "alice",
				name: "bad",
				credential: { kind: "spiffe", spiffeId: "spiffe://example.org" },
			}),
		).rejects.toThrow(/with a path/);
		await expect(
			auth.device?.register({
				ownerId: "alice",
				name: "dup",
				credential: { kind: "spiffe", spiffeId: ROBOT },
			}),
		).rejects.toThrow(/already registered/);
	});

	it("does not authenticate a spiffe credential through the device assertion or psk paths", async () => {
		const r = await auth.device?.authenticate({ kind: "x509", thumbprint: ROBOT });
		expect(r?.ok).toBe(false);
	});
});

describe("agent principal and bound token", () => {
	it("issues a token bound to the SVID certificate, and only that certificate can use it", async () => {
		const agent = await auth.agent.create({
			ownerId: "alice",
			name: "worker",
			type: "autonomous",
			permissions: PERMS,
		});
		const bridge = bridgeFor({ [WORKER]: agent.id });
		const leaf = leafFor(WORKER);
		const r = await bridge.authenticate({ kind: "x509", chain: leaf.pem });
		expect(r).toMatchObject({ ok: true, principal: { type: "agent", agent: { id: agent.id } } });
		if (!r.ok) return;
		const issued = await bridge.issueAgentToken(r);
		expect(issued?.cnf).toEqual(r.cnf);
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const call = (cert?: string) =>
			handler(
				new Request(AUTHORIZE_URL, {
					method: "POST",
					headers: {
						Authorization: `Bearer ${issued?.token}`,
						"Content-Type": "application/json",
						...(cert ? { "x-client-cert-sha256": cert } : {}),
					},
					body: JSON.stringify(CALL),
				}),
			);
		expect((await call(r.svid.thumbprint)).status).toBe(200);
		expect((await call()).status).toBe(401);
		const stolen = await call("d".repeat(43));
		expect(await codeOf(stolen)).toBe("confirmation_failed");
	});

	it("gives no token for a JWT-SVID or a device", async () => {
		const bridge = bridgeFor({
			[WORKER]:
				(await auth.agent.list({ userId: "alice" })).find((a) => a.name === "worker")?.id ?? "",
		});
		const jwt = await bridge.authenticate({
			kind: "jwt",
			token: await jwtSvid(es, { sub: WORKER, aud: AUD }),
		});
		expect(jwt.ok && (await bridge.issueAgentToken(jwt))).toBeNull();
		const dev = await bridge.authenticate({ kind: "x509", chain: leafFor(ROBOT).pem });
		expect(dev.ok && (await bridge.issueAgentToken(dev))).toBeNull();
	});

	it("refuses a revoked agent and never maps an id to a device backing agent", async () => {
		const agent = await auth.agent.create({
			ownerId: "alice",
			name: "gone",
			type: "autonomous",
			permissions: PERMS,
		});
		const id = "spiffe://example.org/ns/prod/sa/gone";
		const bridge = bridgeFor({ [id]: agent.id });
		expect((await bridge.authenticate({ kind: "x509", chain: leafFor(id).pem })).ok).toBe(true);
		await auth.agent.revoke(agent.id);
		expect(await bridge.authenticate({ kind: "x509", chain: leafFor(id).pem })).toMatchObject({
			ok: false,
			code: "principal_inactive",
		});
		const { device } = (await auth.device?.register({ ownerId: "alice", name: "d2" })) as never;
		const sneaky = createSpiffeBridge({
			trustDomains: { "example.org": { roots: [pki.ca.pem] } },
			agents: {
				get: (i) => auth.agent.get(i),
				rotate: (i, o) => auth.agent.rotate(i, o),
				resolve: () => device.agentId,
			},
		});
		expect(
			await sneaky.authenticate({
				kind: "x509",
				chain: leafFor("spiffe://example.org/ns/x/y").pem,
			}),
		).toMatchObject({ ok: false, code: "unknown_workload" });
	});

	it("a map entry on a prototype name does not match", async () => {
		const bridge = bridgeFor({});
		const r = await bridge.authenticate({
			kind: "x509",
			chain: leafFor("spiffe://example.org/constructor").pem,
		});
		expect(r).toMatchObject({ ok: false, code: "unknown_workload" });
	});
});

describe("request entry point", () => {
	it("reads the certificate from the host callback first, then a bearer JWT-SVID", async () => {
		const leaf = leafFor(ROBOT);
		const bridge = createSpiffeBridge({
			trustDomains: {
				"example.org": {
					bundle: bundleDoc({ cas: [pki.ca.der], jwt: [{ kid: es.kid, jwk: es.publicJwk }] }),
				},
			},
			audience: [AUD],
			...(auth.device && { devices: auth.device }),
			clientCertificate: (req) => (req.headers.get("x-test-mtls") ? leaf.pem : null),
		});
		const withCert = await bridge.authenticateRequest(
			new Request("https://x/", { headers: { "x-test-mtls": "1" } }),
		);
		expect(withCert).toMatchObject({ ok: true, svid: { kind: "x509" } });
		const token = await jwtSvid(es, { sub: ROBOT, aud: AUD });
		const withJwt = await bridge.authenticateRequest(
			new Request("https://x/", { headers: { authorization: `Bearer ${token}` } }),
		);
		expect(withJwt).toMatchObject({ ok: true, svid: { kind: "jwt" } });
		expect(await bridge.authenticateRequest(new Request("https://x/"))).toMatchObject({
			ok: false,
			code: "malformed",
		});
		const bad = await bridge.authenticateRequest(
			new Request("https://x/", { headers: { authorization: "Bearer a.b.c" } }),
		);
		expect(bad.ok).toBe(false);
	});

	it("a trust bundle that rotated out stops authenticating its workloads", async () => {
		let doc: unknown = bundleDoc({ cas: [pki.ca.der], sequence: 1, refreshHint: 60 });
		let t = 0;
		const bridge = createSpiffeBridge({
			trustDomains: {
				"example.org": {
					endpoint: {
						url: "https://spire.example/b",
						fetch: (async () => new Response(JSON.stringify(doc))) as unknown as typeof fetch,
					},
				},
			},
			devices: auth.device as NonNullable<typeof auth.device>,
			clock: () => Date.now() + t,
		});
		const chain = leafFor(ROBOT).pem;
		expect((await bridge.authenticate({ kind: "x509", chain })).ok).toBe(true);
		doc = { keys: [], spiffe_sequence: 2 };
		t += 61_000;
		expect(await bridge.authenticate({ kind: "x509", chain })).toMatchObject({
			ok: false,
			code: "untrusted_chain",
		});
	});
});
