import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { auditLogs } from "../src/db/schema.js";
import { createTheAuthHandler } from "../src/http/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import { seedUser, sessionToken } from "./http/helpers.js";
import type { JwtKey, TestPki } from "./spiffe-fixtures.js";
import { bundleDoc, jwtKey, jwtSvid, LEAF_OK, makePki, replaceExt } from "./spiffe-fixtures.js";

const BASE = "http://localhost/api/theauth";
const ROBOT = "spiffe://example.org/ns/prod/sa/robot";
const AGENT_ID = "spiffe://example.org/ns/prod/sa/agent";
const AUD = "https://theauth.example";
const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
let pki: TestPki;
let es: JwtKey;
let auth: TheAuth;
let handler: (r: Request) => Promise<Response>;
let admin: string;
let agentRowId: string;
let revokedRowId = "";
const REVOKED_ID = "spiffe://example.org/ns/prod/sa/revoked";

function leafFor(id: string) {
	return pki.leaf({
		ext: replaceExt(LEAF_OK, "subjectAltName", `subjectAltName=critical,URI:${id}`),
	});
}

function call(path: string, init: RequestInit = {}) {
	return handler(new Request(`${BASE}${path}`, init));
}

function post(path: string, body: unknown, headers: Record<string, string> = {}) {
	return call(path, {
		method: "POST",
		headers: { "content-type": "application/json", ...headers },
		body: JSON.stringify(body),
	});
}

const asAdmin = () => ({ authorization: `Bearer ${admin}` });

async function rows(agentId: string, action: string) {
	return auth.db
		.select()
		.from(auditLogs)
		.where(and(eq(auditLogs.agentId, agentId), eq(auditLogs.action, action)));
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
		},
		devices: {
			spiffe: {
				trustDomains: {
					"example.org": {
						bundle: bundleDoc({ cas: [pki.ca.der], jwt: [{ kid: es.kid, jwk: es.publicJwk }] }),
					},
				},
				audience: [AUD],
				trustedProxyHeader: "x-forwarded-client-cert",
				resolveAgent: (id) =>
					id === AGENT_ID ? agentRowId : id === REVOKED_ID ? revokedRowId : null,
				rateLimit: { max: 1000 },
			},
		},
		auth: { session: { secret: SECRET } },
	});
	handler = createTheAuthHandler(auth, { basePath: "/api/theauth" });
	await seedUser(auth, "alice");
	admin = await sessionToken(auth, "alice");
	const agent = await auth.agent.create({
		ownerId: "alice",
		name: "workload",
		type: "autonomous",
		permissions: [{ resource: "docs", actions: ["read"] }],
	});
	agentRowId = agent.id;
});
afterAll(() => pki.cleanup());

describe("admin routes", () => {
	it("requires authentication on every admin route", async () => {
		for (const path of ["/devices/spiffe/verify", "/devices/spiffe/token", "/devices/x/spiffe"]) {
			const res = await post(path, { kind: "jwt", token: "x" });
			expect(res.status).toBe(401);
		}
	});

	it("links an id in a configured trust domain and refuses a foreign one", async () => {
		const { device } = await (async () => {
			const res = await post(
				"/devices",
				{ ownerId: "alice", name: "robot", permissions: [{ resource: "docs", actions: ["read"] }] },
				asAdmin(),
			);
			return (await res.json()).data as { device: { id: string; agentId: string } };
		})();
		const bad = await post(
			`/devices/${device.id}/spiffe`,
			{ spiffeId: "spiffe://evil.example/ns/x/sa/y" },
			asAdmin(),
		);
		expect(bad.status).toBe(400);
		const none = await post(`/devices/${device.id}/spiffe`, {}, asAdmin());
		expect(none.status).toBe(400);
		const good = await post(`/devices/${device.id}/spiffe`, { spiffeId: ROBOT }, asAdmin());
		expect(good.status).toBe(201);
		expect((await good.json()).data).toMatchObject({ kind: "spiffe", lookup: ROBOT });
		const dup = await post(`/devices/${device.id}/spiffe`, { spiffeId: ROBOT }, asAdmin());
		expect(dup.status).toBe(409);
	});

	it("links by SVID and shows the credential on the device", async () => {
		const res = await post("/devices", { ownerId: "alice", name: "by-svid" }, asAdmin());
		const { device } = (await res.json()).data as { device: { id: string } };
		const id = "spiffe://example.org/ns/prod/sa/by-svid";
		const linked = await post(
			`/devices/${device.id}/spiffe`,
			{ presentation: { kind: "x509", chain: leafFor(id).pem } },
			asAdmin(),
		);
		expect(linked.status).toBe(201);
		const got = await call(`/devices/${device.id}`, { headers: asAdmin() });
		const creds = (await got.json()).data.credentials as Array<{ kind: string; lookup: string }>;
		expect(creds).toContainEqual(expect.objectContaining({ kind: "spiffe", lookup: id }));
		const refused = await post(
			`/devices/${device.id}/spiffe`,
			{ presentation: { kind: "jwt", token: await jwtSvid(es, { sub: id, aud: "other" }) } },
			asAdmin(),
		);
		expect(refused.status).toBe(400);
	});

	it("verifies an SVID for diagnostics and reports failures without a stack", async () => {
		const good = await post(
			"/devices/spiffe/verify",
			{ kind: "jwt", token: await jwtSvid(es, { sub: ROBOT, aud: AUD }) },
			asAdmin(),
		);
		expect(good.status).toBe(200);
		expect((await good.json()).data).toMatchObject({ ok: true, spiffeId: ROBOT });
		const stranger = await post(
			"/devices/spiffe/verify",
			{ kind: "x509", chain: leafFor("spiffe://example.org/ns/prod/sa/nobody").pem },
			asAdmin(),
		);
		expect((await stranger.json()).data).toMatchObject({ ok: false, code: "unknown_workload" });
		const garbage = await post(
			"/devices/spiffe/verify",
			{ kind: "x509", chain: "nope" },
			asAdmin(),
		);
		expect((await garbage.json()).data).toMatchObject({ ok: false, code: "malformed" });
	});

	it("issues a certificate bound agent token for an agent workload, and refuses a device", async () => {
		const dev = await post("/devices/spiffe/token", { chain: leafFor(ROBOT).pem }, asAdmin());
		expect(dev.status).toBe(400);
		const leaf = leafFor(AGENT_ID);
		const res = await post("/devices/spiffe/token", { chain: leaf.pem }, asAdmin());
		expect(res.status).toBe(201);
		const data = (await res.json()).data as {
			agentId: string;
			token: string;
			cnf: Record<string, string>;
		};
		expect(data.agentId).toBe(agentRowId);
		expect(data.token).toMatch(/^[\w-]+/);
		expect(data.cnf["x5t#S256"]).toMatch(/^[A-Za-z0-9_-]{43}$/);
		const audit = await rows(agentRowId, "device.spiffe.authenticate");
		expect(audit.some((r) => r.result === "allowed")).toBe(true);
		const nobody = await post("/devices/spiffe/token", { chain: "nope" }, asAdmin());
		expect(nobody.status).toBe(400);
	});

	it("never mints for another owner's agent", async () => {
		await seedUser(auth, "mallory");
		const other = await sessionToken(auth, "mallory");
		const res = await post(
			"/devices/spiffe/token",
			{ chain: leafFor(AGENT_ID).pem },
			{
				authorization: `Bearer ${other}`,
			},
		);
		expect(res.status).toBe(404);
	});
});

describe("admin route ownership", () => {
	let eve: string;
	let deviceId: string;

	beforeAll(async () => {
		await seedUser(auth, "eve");
		eve = await sessionToken(auth, "eve");
		const res = await post("/devices", { ownerId: "alice", name: "owned-by-alice" }, asAdmin());
		deviceId = ((await res.json()).data as { device: { id: string } }).device.id;
		await post(
			`/devices/${deviceId}/spiffe`,
			{ spiffeId: "spiffe://example.org/ns/prod/sa/alice-dev" },
			asAdmin(),
		);
		const gone = await auth.agent.create({
			ownerId: "alice",
			name: "revoked",
			type: "autonomous",
			permissions: [],
		});
		revokedRowId = gone.id;
		await auth.agent.revoke(gone.id);
	});

	const asEve = () => ({ authorization: `Bearer ${eve}` });

	it("answers not found when a non-owner links an id to another owner's device", async () => {
		const byId = await post(
			`/devices/${deviceId}/spiffe`,
			{ spiffeId: "spiffe://example.org/ns/prod/sa/hijack" },
			asEve(),
		);
		expect(byId.status).toBe(404);
		const bySvid = await post(
			`/devices/${deviceId}/spiffe`,
			{ presentation: { kind: "x509", chain: leafFor("spiffe://example.org/ns/prod/sa/h2").pem } },
			asEve(),
		);
		expect(bySvid.status).toBe(404);
		const unknown = await post(
			"/devices/no-such-device/spiffe",
			{ spiffeId: "spiffe://example.org/ns/prod/sa/x" },
			asEve(),
		);
		expect(unknown.status).toBe(404);
		const got = await call(`/devices/${deviceId}`, { headers: asAdmin() });
		const creds = (await got.json()).data.credentials as Array<{ lookup: string }>;
		expect(creds.some((c) => c.lookup.endsWith("/hijack") || c.lookup.endsWith("/h2"))).toBe(false);
	});

	it("hides another owner's mappings in admin verify", async () => {
		const mine = await post(
			"/devices/spiffe/verify",
			{ kind: "x509", chain: leafFor("spiffe://example.org/ns/prod/sa/alice-dev").pem },
			asAdmin(),
		);
		expect((await mine.json()).data).toMatchObject({ ok: true, principal: { type: "device" } });
		const unknown = await post(
			"/devices/spiffe/verify",
			{ kind: "x509", chain: leafFor("spiffe://example.org/ns/prod/sa/nobody").pem },
			asEve(),
		);
		const expected = (await unknown.json()).data;
		for (const chain of [
			leafFor("spiffe://example.org/ns/prod/sa/alice-dev").pem,
			leafFor(AGENT_ID).pem,
			leafFor(REVOKED_ID).pem,
		]) {
			const res = await post("/devices/spiffe/verify", { kind: "x509", chain }, asEve());
			const data = (await res.json()).data;
			expect(data).toMatchObject({ ok: false, code: "unknown_workload" });
			expect(data.principal).toBeUndefined();
			expect(data.reason).toBe(expected.reason);
		}
		const jwt = await post(
			"/devices/spiffe/verify",
			{ kind: "jwt", token: await jwtSvid(es, { sub: ROBOT, aud: AUD }) },
			asEve(),
		);
		expect((await jwt.json()).data).toMatchObject({ ok: false, code: "unknown_workload" });
	});

	it("does not mint for a non-owner, and answers alike for a device or revoked agent", async () => {
		const agent = await post("/devices/spiffe/token", { chain: leafFor(AGENT_ID).pem }, asEve());
		expect(agent.status).toBe(404);
		const device = await post(
			"/devices/spiffe/token",
			{ chain: leafFor("spiffe://example.org/ns/prod/sa/alice-dev").pem },
			asEve(),
		);
		expect(device.status).toBe(404);
		const revoked = await post(
			"/devices/spiffe/token",
			{ chain: leafFor(REVOKED_ID).pem },
			asEve(),
		);
		expect(revoked.status).toBe(400);
		expect((await revoked.json()).error.code).toBe("UNKNOWN_WORKLOAD");
		const owner = await post(
			"/devices/spiffe/token",
			{ chain: leafFor(REVOKED_ID).pem },
			asAdmin(),
		);
		expect((await owner.json()).error.code).toBe("PRINCIPAL_INACTIVE");
	});

	it("never trusts a chain in the body of the device route", async () => {
		const res = await post("/device/spiffe/verify", {
			kind: "x509",
			chain: leafFor(ROBOT).pem,
			presentation: { kind: "x509", chain: leafFor(ROBOT).pem },
		});
		expect(res.status).toBe(401);
		const withHeader = await post(
			"/device/spiffe/verify",
			{ chain: leafFor(AGENT_ID).pem },
			{ "x-forwarded-client-cert": encodeURIComponent(leafFor(ROBOT).pem) },
		);
		expect((await withHeader.json()).data).toMatchObject({
			spiffeId: ROBOT,
			principal: { type: "device" },
		});
	});
});

describe("device side verify", () => {
	it("verifies a Bearer JWT-SVID and answers 401 with a code otherwise", async () => {
		const ok = await post(
			"/device/spiffe/verify",
			{},
			{
				authorization: `Bearer ${await jwtSvid(es, { sub: ROBOT, aud: AUD })}`,
			},
		);
		expect(ok.status).toBe(200);
		expect((await ok.json()).data).toMatchObject({ ok: true, principal: { type: "device" } });
		const bad = await post(
			"/device/spiffe/verify",
			{},
			{
				authorization: `Bearer ${await jwtSvid(es, { sub: ROBOT, aud: "other" })}`,
			},
		);
		expect(bad.status).toBe(401);
		expect((await bad.json()).error.code).toBe("wrong_audience");
		const none = await post("/device/spiffe/verify", {});
		expect(none.status).toBe(401);
	});

	it("takes the certificate only from the configured proxy header, never the body", async () => {
		const pem = leafFor(ROBOT).pem;
		const fromHeader = await post(
			"/device/spiffe/verify",
			{},
			{
				"x-forwarded-client-cert": encodeURIComponent(pem),
			},
		);
		expect(fromHeader.status).toBe(200);
		const otherHeader = await post(
			"/device/spiffe/verify",
			{},
			{ "x-ssl-client-cert": encodeURIComponent(pem) },
		);
		expect(otherHeader.status).toBe(401);
		const body = await post("/device/spiffe/verify", { kind: "x509", chain: pem });
		expect(body.status).toBe(401);
		const junk = await post("/device/spiffe/verify", {}, { "x-forwarded-client-cert": "%E0%A4%A" });
		expect(junk.status).toBe(401);
	});

	it("honours no header when none is configured", async () => {
		const plain = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
			devices: {
				spiffe: {
					trustDomains: { "example.org": { bundle: bundleDoc({ cas: [pki.ca.der] }) } },
				},
			},
			auth: { session: { secret: SECRET } },
		});
		const h = createTheAuthHandler(plain, { basePath: "/api/theauth" });
		const res = await h(
			new Request(`${BASE}/device/spiffe/verify`, {
				method: "POST",
				headers: { "x-forwarded-client-cert": encodeURIComponent(leafFor(ROBOT).pem) },
			}),
		);
		expect(res.status).toBe(401);
		expect((await res.json()).error.code).toBe("malformed");
	});

	it("rate limits and answers 404 when the bridge is not configured", async () => {
		const limited = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
			devices: {
				spiffe: {
					trustDomains: { "example.org": { bundle: bundleDoc({ cas: [pki.ca.der] }) } },
					rateLimit: { max: 2, windowSeconds: 60 },
				},
			},
			auth: { session: { secret: SECRET } },
		});
		const h = createTheAuthHandler(limited, { basePath: "/api/theauth" });
		const hit = () => h(new Request(`${BASE}/device/spiffe/verify`, { method: "POST" }));
		expect((await hit()).status).toBe(401);
		expect((await hit()).status).toBe(401);
		const third = await hit();
		expect(third.status).toBe(429);
		expect(third.headers.get("retry-after")).toBe("60");

		const off = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
			devices: {},
			auth: { session: { secret: SECRET } },
		});
		const offHandler = createTheAuthHandler(off, { basePath: "/api/theauth" });
		const res = await offHandler(new Request(`${BASE}/device/spiffe/verify`, { method: "POST" }));
		expect(res.status).toBe(404);
	});
});

describe("audit", () => {
	it("writes a row per outcome for an attributable device, without the certificate", async () => {
		const id = "spiffe://example.org/ns/prod/sa/audited";
		const reg = await post("/devices", { ownerId: "alice", name: "audited" }, asAdmin());
		const { device } = (await reg.json()).data as { device: { id: string; agentId: string } };
		await post(`/devices/${device.id}/spiffe`, { spiffeId: id }, asAdmin());
		const leaf = leafFor(id);
		await post(
			"/device/spiffe/verify",
			{},
			{ "x-forwarded-client-cert": encodeURIComponent(leaf.pem) },
		);
		// Wrong audience: the signature is fine but the verifier refuses, and the id is only a claim.
		await post(
			"/device/spiffe/verify",
			{},
			{
				authorization: `Bearer ${await jwtSvid(es, { sub: id, aud: "other" })}`,
			},
		);
		const all = await rows(device.agentId, "device.spiffe.authenticate");
		expect(all).toHaveLength(2);
		const allowed = all.find((r) => r.result === "allowed");
		const denied = all.find((r) => r.result === "denied");
		expect(allowed).toBeTruthy();
		expect(denied?.reason).toBe("wrong_audience");
		const stored = JSON.stringify(all);
		expect(stored).not.toContain("BEGIN CERTIFICATE");
		expect(stored).toContain("thumbprint");
		expect(JSON.stringify(denied?.parameters)).toContain('"verified":false');
	});

	it("writes nothing for a failure it cannot tie to a device or agent", async () => {
		const before = await auth.db.select().from(auditLogs);
		await post("/device/spiffe/verify", {}, { authorization: "Bearer not.a.jwt" });
		const after = await auth.db.select().from(auditLogs);
		expect(after.length).toBe(before.length);
	});
});
