#!/usr/bin/env node
/**
 * Benchmark runner. Writes one JSON file with every measurement.
 *
 *   node benchmarks/run.mjs --profile smoke          tiny run, proves the harness works
 *   node benchmarks/run.mjs --profile full           the real run, meant for CI
 *
 * Flags: --profile smoke|full, --backends a,b, --scenarios a,b, --out path,
 * --iterations n (overrides the profile's base count).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { BACKENDS, cleanupTempFiles, createFixture, loadCore } from "./lib/backends.mjs";
import { hardware } from "./lib/env.mjs";
import * as agentsTokens from "./scenarios/agents-tokens.mjs";
import * as audit from "./scenarios/audit.mjs";
import * as authorize from "./scenarios/authorize.mjs";
import * as sessions from "./scenarios/sessions.mjs";
import * as standalone from "./scenarios/standalone.mjs";

const PROFILES = {
	smoke: {
		fast: 200,
		db: 200,
		audit: 200,
		slow: 5,
		warmup: 10,
		contention: [1, 2],
		instances: [],
		instanceIterations: 0,
	},
	full: {
		fast: 200_000,
		db: 2_000,
		audit: 2_000,
		slow: 200,
		warmup: 200,
		contention: [1, 4, 16, 64],
		instances: [2, 4, 8],
		instanceIterations: 400,
	},
};

function parseArgs(argv) {
	const args = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (!a.startsWith("--")) continue;
		const key = a.slice(2);
		const next = argv[i + 1];
		if (next === undefined || next.startsWith("--")) args[key] = "true";
		else {
			args[key] = next;
			i++;
		}
	}
	return args;
}

const args = parseArgs(process.argv.slice(2));
const profileName = args.profile ?? "smoke";
const base = PROFILES[profileName];
if (!base) {
	console.error(`Unknown profile "${profileName}". Use smoke or full.`);
	process.exit(2);
}
const profile = { ...base };
if (args.iterations) {
	const n = Number(args.iterations);
	profile.fast = n;
	profile.db = n;
	profile.audit = n;
}

const dbScenarios = { "agents-tokens": agentsTokens, authorize, sessions, audit };
const wantedScenarios = args.scenarios
	? args.scenarios.split(",")
	: [...Object.keys(dbScenarios), "standalone"];
const wantedBackends = args.backends
	? args.backends.split(",")
	: Object.entries(BACKENDS)
			.filter(([, b]) => profileName !== "smoke" || b.smoke)
			.map(([key]) => key);

const out = resolve(args.out ?? `benchmarks/results/${profileName}.json`);
const results = [];
const skipped = [];
const failures = [];

function record(row) {
	results.push(row);
	const l = row.latencyMs;
	console.log(
		`${row.backend.padEnd(22)} ${row.scenario.padEnd(18)} ${row.variant.slice(0, 60).padEnd(60)} p50=${l.p50}ms p99=${l.p99}ms ${row.opsPerSec} ops/s${row.errors ? ` errors=${row.errors}` : ""}`,
	);
}

const core = await loadCore();

if (wantedScenarios.includes("standalone")) {
	try {
		await standalone.run(core, profile, record);
	} catch (err) {
		failures.push({
			backend: "none",
			scenario: "standalone",
			message: String(err?.message ?? err),
		});
		console.error("standalone failed:", err);
	}
}

for (const backendName of wantedBackends) {
	if (!BACKENDS[backendName]) {
		console.error(`Unknown backend "${backendName}". Known: ${Object.keys(BACKENDS).join(", ")}`);
		process.exit(2);
	}
	const fx = await createFixture(backendName);
	if (!fx) {
		skipped.push({
			backend: backendName,
			reason: "no connection URL in env (DATABASE_URL, POSTGRES_URL or MYSQL_URL)",
		});
		console.log(`skipping ${backendName}: no connection URL`);
		continue;
	}
	for (const [key, mod] of Object.entries(dbScenarios)) {
		if (!wantedScenarios.includes(key)) continue;
		try {
			await mod.run(fx, profile, record);
		} catch (err) {
			failures.push({ backend: backendName, scenario: key, message: String(err?.message ?? err) });
			console.error(`${backendName}/${key} failed:`, err);
		}
	}
}

const payload = {
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	profile: profileName,
	profileSettings: profile,
	command: `node ${["benchmarks/run.mjs", ...process.argv.slice(2)].join(" ")}`,
	hardware: hardware(),
	skippedBackends: skipped,
	failures,
	results,
};
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(payload, null, 2)}\n`);
cleanupTempFiles();
console.log(`wrote ${results.length} measurements to ${out}`);
process.exit(failures.length > 0 ? 1 : 0);
