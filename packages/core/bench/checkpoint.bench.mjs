// Benchmark for audit checkpoints through the public API on a real in-memory SQLite log:
// createCheckpoint, repeated createInclusionProof / createReceipt calls, and the offline verify.
// Run after `pnpm --filter @glinr/theauth build`: node packages/core/bench/checkpoint.bench.mjs
// Optional: ROWS=5000 node packages/core/bench/checkpoint.bench.mjs

import {
	createCheckpoint,
	createInclusionProof,
	createReceipt,
	enableAuditChain,
	generateCheckpointKeyPair,
	insertAuditRow,
	verifyInclusionProof,
	verifyReceipt,
} from "../dist/audit/index.js";
import { agents, createDatabase, createTables, users } from "../dist/index.js";

const ROWS = Number(process.env.ROWS ?? 3000);
const RUNS = 5;
const T0 = new Date("2026-10-01T00:00:00Z");
const out = (line) => process.stdout.write(`${line}\n`);

async function time(fn) {
	const t0 = performance.now();
	const value = await fn();
	return { ms: performance.now() - t0, value };
}

function summarize(samples) {
	const sorted = [...samples].sort((a, b) => a - b);
	const fmt = (v) => v.toFixed(1);
	return `first ${fmt(samples[0])} ms, min ${fmt(sorted[0])} ms, median ${fmt(sorted[Math.floor(sorted.length / 2)])} ms`;
}

function unwrap(result, label) {
	if (!result.success) throw new Error(`${label} failed: ${JSON.stringify(result.error)}`);
	return result.data;
}

async function seed() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	await db.insert(users).values({
		id: "u1",
		email: "u1@example.com",
		name: "U1",
		username: "u1",
		createdAt: T0,
		updatedAt: T0,
	});
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		status: "active",
		tokenHash: "h",
		tokenPrefix: "kv_x",
		metadata: {},
		createdAt: T0,
		updatedAt: T0,
	});
	enableAuditChain(db, { hmacKey: "bench-key" });
	for (let i = 0; i < ROWS; i++) {
		await insertAuditRow(db, {
			id: `r${String(i).padStart(7, "0")}`,
			agentId: "a1",
			userId: "u1",
			action: "execute",
			resource: `mcp:github:tool${i % 50}`,
			parameters: { n: i, note: "x".repeat(200) },
			result: "allowed",
			reason: null,
			durationMs: 1,
			timestamp: new Date(T0.getTime() + i * 1000),
			approverId: "u1",
		});
	}
	return db;
}

const db = await seed();
const kp = await generateCheckpointKeyPair("bench-key");
const cpRun = await time(() => createCheckpoint(db, { signer: kp.signer }));
const checkpoint = unwrap(cpRun.value, "createCheckpoint");
const proofMs = [];
const receiptMs = [];
let proof;
for (let r = 0; r < RUNS; r++) {
	const idx = Math.floor((ROWS * (r + 1)) / (RUNS + 1));
	const id = `r${String(idx).padStart(7, "0")}`;
	const p = await time(() => createInclusionProof(db, id, checkpoint));
	proof = unwrap(p.value, "createInclusionProof");
	proofMs.push(p.ms);
	const rc = await time(() => createReceipt(db, id, checkpoint, { reveal: ["action"] }));
	const receipt = unwrap(rc.value, "createReceipt");
	receiptMs.push(rc.ms);
	if (!(await verifyReceipt(receipt, kp.publicKey)).valid) throw new Error("receipt invalid");
}
const verify = await time(() => verifyInclusionProof(proof, checkpoint, kp.publicKey));
if (!verify.value.valid) throw new Error("proof invalid");
out(`rows: ${ROWS}, proof/receipt calls: ${RUNS}, root: ${checkpoint.rootHash}`);
out(`createCheckpoint: ${cpRun.ms.toFixed(1)} ms`);
out(`createInclusionProof: ${summarize(proofMs)}`);
out(`createReceipt: ${summarize(receiptMs)}`);
out(`verifyInclusionProof (offline): ${verify.ms.toFixed(1)} ms`);
