/**
 * Run the device conformance kit at scale and print latency percentiles and memory.
 *
 *   pnpm --filter @glinr/theauth exec jiti scripts/device-fleet-bench.ts [devices]
 *
 * One process, in memory SQLite, one machine. The numbers describe the library under a virtual clock,
 * not a deployed service: there is no network and no real database round trip.
 */
import {
	createDeviceFleet,
	runDeviceConformance,
	sampleMemory,
} from "../src/testing/devices/index.js";

const size = Number(process.argv[2] ?? 1000);
const before = sampleMemory();
const started = performance.now();
const fleet = await createDeviceFleet({ size });
const enrolledMs = performance.now() - started;
const report = await runDeviceConformance(fleet);
const totalMs = performance.now() - started;
const after = sampleMemory();
fleet.dispose();

const rows = Object.entries(fleet.latency.report()).map(([name, s]) => ({
	operation: name,
	calls: s.count,
	p50_ms: Number(s.p50Ms.toFixed(2)),
	p99_ms: Number(s.p99Ms.toFixed(2)),
	max_ms: Number(s.maxMs.toFixed(2)),
}));
process.stdout.write(
	`${JSON.stringify(
		{
			devices: size,
			node: process.version,
			platform: `${process.platform} ${process.arch}`,
			passed: report.passed,
			scenarios: report.scenarios.map((s) => ({
				name: s.name,
				checks: s.checks,
				failures: s.failures.length,
			})),
			enrollAndSetupSeconds: Number((enrolledMs / 1000).toFixed(1)),
			totalSeconds: Number((totalMs / 1000).toFixed(1)),
			memoryMb: { before, after },
			latency: rows,
		},
		null,
		2,
	)}\n`,
);
