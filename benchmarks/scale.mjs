#!/usr/bin/env node
/**
 * Hot path timings on a database with filler rows, where a missing index or a per row query shows up.
 * Needs the bundle from benchmarks/micro-build.mjs (it carries better-sqlite3 and the internals).
 *
 *   node benchmarks/scale.mjs --entry packages/core/.bench/micro-after.mjs --rows 50000 --runs 5
 *
 * Seeds `--rows` agents with 4 permissions each and one delegation link each (a third revoked), a
 * real three hop chain, 100 pending quorum approvals and 2000 live links with votes, then reports the
 * median ms per operation over `--runs` runs. SQLite (better-sqlite3, file) only.
 * `--mcp` turns the MCP module on (its migration adds the delegation chain indexes by itself and the delegation impact list needs its tables). `--drop-indexes` removes the 0014 indexes after boot, to show what they are worth on the current code.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const flag = (n, d) => {
	const i = argv.indexOf(`--${n}`);
	return i >= 0 ? argv[i + 1] : d;
};
const m = await import(
	pathToFileURL(resolve(flag("entry", "packages/core/.bench/micro.mjs"))).href
);
const N = Number(flag("rows", "50000"));
const runs = Number(flag("runs", "5"));
const dir = mkdtempSync(join(tmpdir(), "theauth-scale-"));
const file = join(dir, "scale.db");

try {
	const a = await m.createTheAuth({
		database: { provider: "sqlite-native", url: file },
		agents: { enabled: true, defaultPermissions: [], auditAll: false, tokenExpiry: "24h" },
		...(argv.includes("--mcp") && {
			mcp: {
				enabled: true,
				issuer: "https://auth.example.test",
				baseUrl: "https://auth.example.test/api/auth",
				signingSecret: "scale-benchmark-secret-at-least-32-bytes!!",
			},
		}),
	});
	const raw = new m.Database(file);
	const now = Date.now();
	const user = raw.prepare(
		"insert into theauth_users (id,email,name,created_at,updated_at) values (?,?,?,?,?)",
	);
	user.run("uX", "x@x.test", "x", now, now);
	user.run("uY", "y@x.test", "y", now, now);
	const insA = raw.prepare(
		"insert into theauth_agents (id,owner_id,name,type,status,token_hash,token_prefix,created_at,updated_at) values (?,?,?,?,?,?,?,?,?)",
	);
	const insP = raw.prepare(
		"insert into theauth_permissions (id,agent_id,resource,actions,created_at) values (?,?,?,?,?)",
	);
	const insD = raw.prepare(
		"insert into theauth_delegation_chains (id,from_agent_id,to_agent_id,permissions,depth,max_depth,status,expires_at,created_at) values (?,?,?,?,?,?,?,?,?)",
	);
	const insR = raw.prepare(
		"insert into theauth_approval_requests (id,agent_id,user_id,action,resource,arguments,status,expires_at,created_at,required_approvals) values (?,?,?,?,?,?,?,?,?,?)",
	);
	const insV = raw.prepare(
		"insert into theauth_approval_votes (approval_id,approver_id,decided_at) values (?,?,?)",
	);
	raw.exec("begin");
	for (let i = 0; i < N; i++)
		insA.run(`fa${i}`, "uX", `f${i}`, "autonomous", "active", `hash${i}`, "p", now, now);
	for (let i = 0; i < N; i++) {
		for (let j = 0; j < 4; j++) insP.run(`fp${i}_${j}`, `fa${i}`, `tool:r${j}`, '["read"]', now);
		insD.run(
			`fd${i}`,
			`fa${i}`,
			`fa${(i + 1) % N}`,
			'[{"resource":"tool:x","actions":["read"]}]',
			1,
			3,
			i % 3 === 0 ? "revoked" : "active",
			now + 3e10,
			now - i,
		);
	}
	for (let i = 0; i < 100; i++) {
		insR.run(`ap${i}`, "fa0", "uX", "send", `mail:${i}`, "{}", "pending", now + 3.6e6, now - i, 3);
		insV.run(`ap${i}`, "approver-a", now);
		insV.run(`ap${i}`, "approver-b", now + 1);
	}
	raw.exec("commit");
	if (argv.includes("--drop-indexes")) {
		for (const ix of [
			"theauth_agents_token_hash",
			"theauth_agents_owner_status",
			"theauth_delegation_chains_to",
			"theauth_delegation_chains_from",
			"theauth_rate_limits_lookup",
			"theauth_approval_requests_status",
			"theauth_permissions_agent",
		]) {
			raw.exec(`drop index if exists ${ix}`);
		}
	}
	const PERMS = [{ resource: "tool:*", actions: ["read"] }];
	const ids = [];
	for (let i = 0; i <= 3; i++) {
		ids.push(
			(
				await a.agent.create({
					ownerId: "uY",
					name: `c${i}`,
					type: "delegated",
					permissions: i === 0 ? PERMS : [],
				})
			).id,
		);
	}
	for (let i = 0; i < 3; i++) {
		await a.delegate({
			fromAgent: ids[i],
			toAgent: ids[i + 1],
			permissions: PERMS,
			expiresAt: new Date(now + 3e10),
			maxDepth: 3,
		});
	}
	const tokenAgent = await a.agent.create({
		ownerId: "uY",
		name: "tok",
		type: "autonomous",
		permissions: PERMS,
	});

	const cases = [
		[
			"authorize, delegated depth 3",
			100,
			() => a.authorize(ids[3], { action: "read", resource: "tool:search" }),
		],
		[
			"authorize, direct permission",
			200,
			() => a.authorize(ids[0], { action: "read", resource: "tool:search" }),
		],
		[
			"agent token lookup (authorizeByToken path)",
			200,
			() => a.agent.validateToken(tokenAgent.token),
		],
		["admin list: pending approvals, 100 quorum rows", 20, () => m.listPendingApprovals(a.db, 100)],
		...(argv.includes("--mcp")
			? [["admin list: delegation impact", 5, () => m.delegationImpact(a.db)]]
			: []),
	];
	console.log(
		`rows=${N} runs=${runs}${argv.includes("--drop-indexes") ? " (indexes dropped)" : ""}`,
	);
	const out = [];
	for (const [label, per, fn] of cases) {
		for (let i = 0; i < Math.ceil(per / 5); i++) await fn();
		const meds = [];
		for (let r = 0; r < runs; r++) {
			const t = performance.now();
			for (let i = 0; i < per; i++) await fn();
			meds.push((performance.now() - t) / per);
		}
		meds.sort((x, y) => x - y);
		const med = meds[Math.floor(meds.length / 2)];
		const spread = ((meds[meds.length - 1] - meds[0]) / med) * 100;
		out.push({ label, medianMs: Number(med.toFixed(3)), spreadPct: Number(spread.toFixed(1)) });
		console.log(
			`${label.padEnd(50)} ${med.toFixed(3).padStart(9)} ms/op  spread ${spread.toFixed(1)}%`,
		);
	}
	if (flag("out"))
		(await import("node:fs")).writeFileSync(
			resolve(flag("out")),
			JSON.stringify({ rows: N, runs, results: out }, null, 2),
		);
} finally {
	rmSync(dir, { recursive: true, force: true });
}
