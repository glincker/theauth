// Micro benchmark: theauth.authorize() through a 5 hop delegation chain on the
// in-memory SQLite store. The caller holds no own permissions, so every call
// takes the delegated path: own denial, chain walk, permission evaluation.
//
// Run (after `pnpm --filter @glinr/theauth build`, which produces dist/):
//   node packages/core/bench/authorize.bench.mjs
//
// Env (optional): BENCH_SECONDS (measured window, default 5), BENCH_WARMUP (default 500 calls).

import { createTheAuth, users } from "../dist/index.js";

const HOPS = 5;
const MEASURE_SECONDS = Number(process.env.BENCH_SECONDS ?? 5);
const WARMUP_CALLS = Number(process.env.BENCH_WARMUP ?? 500);
const REQUEST = { action: "read", resource: "mcp:github:repos" };
const ONE_HOUR = 60 * 60 * 1000;

async function setup() {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 100,
			defaultPermissions: [],
			auditAll: false,
			tokenExpiry: "24h",
		},
	});
	theauth.db
		.insert(users)
		.values({
			id: "bench-user",
			email: "bench@example.com",
			name: "Bench User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	const chain = [];
	for (let i = 0; i <= HOPS; i++) {
		chain.push(
			await theauth.agent.create({
				ownerId: "bench-user",
				name: `bench-hop-${i}`,
				type: "delegated",
				permissions: i === 0 ? [{ resource: "mcp:github:*", actions: ["read"] }] : [],
			}),
		);
	}
	for (let i = 0; i < HOPS; i++) {
		await theauth.delegate({
			fromAgent: chain[i].id,
			toAgent: chain[i + 1].id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + ONE_HOUR),
			maxDepth: HOPS + 3,
		});
	}
	return { theauth, leaf: chain[HOPS].id };
}

function percentile(sorted, p) {
	const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
	return sorted[Math.max(0, idx)];
}

async function main() {
	const { theauth, leaf } = await setup();

	const probe = await theauth.authorize(leaf, REQUEST);
	if (!probe.allowed) {
		throw new Error(`bench precondition failed: leaf not allowed (${probe.reason})`);
	}

	for (let i = 0; i < WARMUP_CALLS; i++) {
		await theauth.authorize(leaf, REQUEST);
	}

	const latencies = [];
	const deadline = performance.now() + MEASURE_SECONDS * 1000;
	const startedAt = performance.now();
	while (performance.now() < deadline) {
		const t0 = performance.now();
		await theauth.authorize(leaf, REQUEST);
		latencies.push(performance.now() - t0);
	}
	const elapsedSeconds = (performance.now() - startedAt) / 1000;

	const sorted = [...latencies].sort((a, b) => a - b);
	const mean = sorted.reduce((sum, v) => sum + v, 0) / sorted.length;

	console.log(`authorize() via ${HOPS}-hop delegation chain, in-memory SQLite`);
	console.log(`calls:      ${sorted.length} in ${elapsedSeconds.toFixed(2)} s`);
	console.log(`ops/sec:    ${(sorted.length / elapsedSeconds).toFixed(0)}`);
	console.log(`mean:       ${mean.toFixed(3)} ms`);
	console.log(`p50:        ${percentile(sorted, 50).toFixed(3)} ms`);
	console.log(`p99:        ${percentile(sorted, 99).toFixed(3)} ms`);
	console.log(`max:        ${sorted[sorted.length - 1].toFixed(3)} ms`);
	process.exit(0);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
