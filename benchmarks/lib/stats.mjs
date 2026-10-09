import { performance } from "node:perf_hooks";

/** Nearest-rank percentile over an already sorted array. */
export function percentile(sorted, p) {
	if (sorted.length === 0) return null;
	const rank = Math.ceil((p / 100) * sorted.length);
	return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

function round(n, digits = 4) {
	if (n === null || Number.isNaN(n)) return null;
	const f = 10 ** digits;
	return Math.round(n * f) / f;
}

function rssMb() {
	return process.memoryUsage().rss / (1024 * 1024);
}

function tryGc() {
	if (typeof globalThis.gc === "function") globalThis.gc();
}

/**
 * Time `fn` many times and summarize the latencies.
 *
 * `fn(i)` receives a zero-based operation index that is unique across all
 * workers, so a scenario can derive unique ids from it. Warmup operations are
 * not recorded. With `concurrency` > 1 that many workers pull from a shared
 * counter. These are async tasks on one event loop, not threads, so the number
 * measures how a backend behaves under interleaved awaits, not CPU parallelism.
 */
export async function measure(fn, options) {
	const { iterations, warmup = 0, concurrency = 1 } = options;
	let next = 0;
	for (let i = 0; i < warmup; i++) await fn(-1 - i);

	tryGc();
	const rssBefore = rssMb();
	const latencies = new Array(iterations);
	let errors = 0;
	let firstError = null;
	let completed = 0;

	async function worker() {
		for (;;) {
			const i = next++;
			if (i >= iterations) return;
			const t0 = performance.now();
			try {
				await fn(i);
			} catch (err) {
				errors++;
				firstError ??= err instanceof Error ? err.message : String(err);
			}
			latencies[completed++] = performance.now() - t0;
		}
	}

	const start = performance.now();
	await Promise.all(Array.from({ length: concurrency }, () => worker()));
	const wallMs = performance.now() - start;
	const rssAfter = rssMb();
	tryGc();
	const rssAfterGc = rssMb();

	const sorted = latencies.slice(0, completed).sort((a, b) => a - b);
	const sum = sorted.reduce((a, b) => a + b, 0);
	return {
		iterations: completed,
		concurrency,
		errors,
		firstError,
		wallMs: round(wallMs, 2),
		opsPerSec: round(wallMs > 0 ? (completed / wallMs) * 1000 : 0, 1),
		latencyMs: {
			min: round(sorted[0] ?? null),
			mean: round(completed > 0 ? sum / completed : null),
			p50: round(percentile(sorted, 50)),
			p95: round(percentile(sorted, 95)),
			p99: round(percentile(sorted, 99)),
			max: round(sorted[sorted.length - 1] ?? null),
		},
		rssDeltaMb: round(rssAfter - rssBefore, 2),
		rssDeltaAfterGcMb:
			typeof globalThis.gc === "function" ? round(rssAfterGc - rssBefore, 2) : null,
	};
}
