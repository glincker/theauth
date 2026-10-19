#!/usr/bin/env node
/**
 * Micro benchmarks for the pure CPU hot paths: resource matching, approval hash canonicalization,
 * offline device bundle verify, MCP token validation (with and without revocation lookups), DPoP proof
 * verify and stateless session verify. No database. Prints one JSON document.
 *
 *   node benchmarks/micro-build.mjs packages/core/.bench/micro-after.mjs
 *   node benchmarks/micro.mjs --entry packages/core/.bench/micro-after.mjs --runs 7 --out results/micro.json
 *
 * Each case runs `--runs` times; the report keeps every run's median per operation (ns) plus the median of
 * those medians and the spread, so noise is visible.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { hardware } from "./lib/env.mjs";

const argv = process.argv.slice(2);
const flag = (n, d) => {
	const i = argv.indexOf(`--${n}`);
	return i >= 0 ? argv[i + 1] : d;
};
const entry = resolve(flag("entry", "packages/core/.bench/micro.mjs"));
const runs = Number(flag("runs", "7"));
const only = flag("only", "");
/** `--clock cpu` times process CPU (user plus system, all threads) instead of wall time, which holds up better on a busy laptop. */
const cpu = flag("clock", "wall") === "cpu";
const m = await import(pathToFileURL(entry).href);
const { exportJWK, generateKeyPair, SignJWT } = m;

const ISSUER = "https://auth.theauth.test";
const RESOURCE = "https://mcp.theauth.test";
const SECRET = "test-signing-secret-at-least-32-chars-long!!";

const median = (a) => {
	const s = [...a].sort((x, y) => x - y);
	return s[Math.floor(s.length / 2)];
};

/** Time `fn` in batches; returns the median per-op ns across batches. */
async function timeOnce(fn, batches, perBatch) {
	const per = [];
	for (let b = 0; b < batches; b++) {
		const c0 = process.cpuUsage();
		const t0 = performance.now();
		for (let i = 0; i < perBatch; i++) await fn(i);
		const wallNs = ((performance.now() - t0) * 1e6) / perBatch;
		const c = process.cpuUsage(c0);
		const cpuNs = ((c.user + c.system) * 1e3) / perBatch;
		per.push(cpu ? cpuNs : wallNs);
	}
	return median(per);
}

const cases = [];
const add = (name, perBatch, fn) => cases.push({ name, perBatch, fn });

// 1. matching
const perms50 = Array.from({ length: 50 }, (_, i) => ({
	resource: `tool:svc${i}:*`,
	actions: ["read"],
}));
perms50.push({ resource: "tool:search", actions: ["read"] });
add("match colon, 50 perms, last hit", 2000, () =>
	m.findMatchingPermission(perms50, "read", "tool:search", "colon"),
);
add("match colon, 50 perms, miss", 2000, () =>
	m.findMatchingPermission(perms50, "read", "tool:missing", "colon"),
);
const pathPerms = [
	{ resource: "ros2:/fleet/*/cmd_vel", actions: ["publish"] },
	{ resource: "ros2:/fleet/**/status", actions: ["subscribe"] },
	{ resource: "ros2:/arm/joint_states", actions: ["subscribe"] },
];
add("match path, glob hit (1 slash segment)", 2000, () =>
	m.findMatchingPermission(pathPerms, "publish", "ros2:/fleet/robot7/cmd_vel", "path"),
);
add("match path, deep ** hit", 2000, () =>
	m.findMatchingPermission(pathPerms, "subscribe", "ros2:/fleet/a/b/c/d/e/status", "path"),
);
add("match path, glob miss", 2000, () =>
	m.findMatchingPermission(pathPerms, "publish", "ros2:/fleet/robot7/other", "path"),
);

// 2. canonical approval json
const args = {
	to: "ops@example.com",
	subject: "Quarterly <report> & summary",
	amount: 1234.5,
	tags: ["a", "b", "c", "d"],
	nested: { z: 1, a: [1, 2, { k: "v", b: null }], m: "  text" },
	rows: Array.from({ length: 20 }, (_, i) => ({ id: i, name: `item-${i}`, ok: i % 2 === 0 })),
};
add("canonicalApprovalJson, ~20 row payload", 500, () => m.canonicalApprovalJson(args));

// 3. device bundle
{
	const pair = await generateKeyPair("ES256", { extractable: true });
	const signing = { alg: "ES256", kid: "k1", privateKey: await exportJWK(pair.privateKey) };
	const pub = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
	const issued = await m.signDeviceBundle({
		signing,
		issuer: "theauth",
		deviceId: "dev_1",
		ownerId: "u1",
		groups: ["yard"],
		permissions: [
			{ resource: "mqtt:sensors:*", actions: ["publish"] },
			{ resource: "coap:gate", actions: ["put"] },
		],
		ttlSeconds: 3600,
	});
	const jwks = { keys: [pub] };
	add("device bundle verify (JWKS object)", 200, async () => {
		const r = await m.verifyDeviceBundle(issued.token, { keys: jwks, deviceId: "dev_1" });
		if (!r.ok) throw new Error(r.message);
	});
	add("device bundle sign", 100, () =>
		m.signDeviceBundle({
			signing,
			issuer: "theauth",
			deviceId: "dev_1",
			ownerId: "u1",
			groups: [],
			permissions: [],
			ttlSeconds: 3600,
		}),
	);
	add("device bundle evaluate (offline decision)", 2000, () =>
		m.evaluateDeviceBundle(issued.claims, { action: "publish", resource: "mqtt:sensors:t1" }),
	);
}

// 4. MCP token validation
{
	const denylist = new Set();
	for (let i = 0; i < 5000; i++) denylist.add(`jti_revoked_${i}`);
	const revocations = {
		hits: denylist,
		async revoke() {},
		async revokeMany() {},
		async isRevoked(jti) {
			return denylist.has(jti);
		},
		async check(q) {
			return denylist.has(q.jti)
				? { kind: "jti", id: q.jti, revokedAt: new Date(), reason: "x" }
				: null;
		},
		async fingerprint() {
			return "1";
		},
		async prune() {
			return 0;
		},
	};
	const ctxFor = (mode) => {
		const ctx = {
			config: {
				enabled: true,
				issuer: ISSUER,
				baseUrl: `${ISSUER}/api/auth`,
				signingSecret: SECRET,
				resource: RESOURCE,
				accessTokenTtl: 3600,
				refreshTokenTtl: 86400,
				refreshTokenAbsoluteTtl: 86400,
				codeTtl: 60,
				revocation: { mode },
			},
		};
		m.attachFreshnessDeps(ctx, { revocations });
		return ctx;
	};
	const now = Math.floor(Date.now() / 1000);
	const token = await new SignJWT({ scope: "mcp:read", client_id: "client_1" })
		.setProtectedHeader({ alg: "HS256" })
		.setIssuer(ISSUER)
		.setAudience(RESOURCE)
		.setSubject("user_1")
		.setJti("jti_ok")
		.setIssuedAt(now)
		.setExpirationTime(now + 86400)
		.sign(new TextEncoder().encode(SECRET));
	for (const mode of ["offline", "cached", "live"]) {
		const ctx = ctxFor(mode);
		add(`mcp validateAccessToken HS256, ${mode}, 5000-entry denylist`, 200, async () => {
			const r = await m.validateAccessToken(ctx, token, { expectedAudience: RESOURCE });
			if (!r.success) throw new Error(r.error.message);
		});
	}
}

// 5. DPoP proof verify
{
	const pair = await generateKeyPair("ES256", { extractable: true });
	const jwk = await exportJWK(pair.publicKey);
	const storage = m.memoryStorage();
	const deps = { config: { enabled: true }, storage, prefix: "b:" };
	let n = 0;
	const proofs = [];
	for (let i = 0; i < 3000; i++) {
		proofs.push(
			await new SignJWT({ htm: "POST", htu: `${RESOURCE}/tools`, jti: `jti-${i}` })
				.setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
				.setIssuedAt()
				.sign(pair.privateKey),
		);
	}
	add("dpop proof verify (ES256, fresh jti each)", 200, async () => {
		const r = await m.verifyDpopProofWith(deps, {
			proof: proofs[n++ % proofs.length],
			method: "POST",
			url: `${RESOURCE}/tools`,
		});
		if (!r.success && n < proofs.length) throw new Error(r.error.message);
	});
}

// 6. stateless session verify
{
	const sessions = m.createStatelessSessions({ secret: SECRET });
	const created = await sessions.createSession({ sub: "user_1", email: "a@example.com" });
	const cookie = created.data.headers[0].split(";")[0];
	add("stateless getSession (HMAC verify)", 1000, async () => {
		if (!(await sessions.getSession(cookie))) throw new Error("no session");
	});
}

const results = [];
for (const c of cases) {
	if (only && !c.name.includes(only)) continue;
	await timeOnce(c.fn, 3, Math.max(20, Math.floor(c.perBatch / 4)));
	const medians = [];
	for (let r = 0; r < runs; r++) medians.push(await timeOnce(c.fn, 9, c.perBatch));
	const med = median(medians);
	const spread = ((Math.max(...medians) - Math.min(...medians)) / med) * 100;
	results.push({
		name: c.name,
		medianNs: Math.round(med),
		minNs: Math.round(Math.min(...medians)),
		maxNs: Math.round(Math.max(...medians)),
		spreadPct: Number(spread.toFixed(1)),
		runs,
	});
	console.log(
		`${c.name.padEnd(62)} ${String(Math.round(med)).padStart(9)} ns/op  spread ${spread.toFixed(1)}%`,
	);
}
const outPath = flag("out", "");
if (outPath) {
	mkdirSync(dirname(resolve(outPath)), { recursive: true });
	writeFileSync(
		resolve(outPath),
		`${JSON.stringify({ generatedAt: new Date().toISOString(), node: process.version, hardware: hardware(), runs, results }, null, 2)}\n`,
	);
}
