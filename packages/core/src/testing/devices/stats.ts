/** Latency and memory numbers for fleet runs. Wall time comes from `performance.now()`, which the virtual clock does not touch. */
export interface LatencySummary {
	count: number;
	p50Ms: number;
	p99Ms: number;
	maxMs: number;
	meanMs: number;
}

/** Nearest rank percentile of an unsorted list. `p` is 0 to 100. */
export function percentile(values: readonly number[], p: number): number {
	if (values.length === 0) return 0;
	const sorted = [...values].sort((a, b) => a - b);
	const rank = Math.max(1, Math.ceil((p / 100) * sorted.length));
	return sorted[Math.min(rank, sorted.length) - 1] as number;
}

export function summarize(samples: readonly number[]): LatencySummary {
	const sum = samples.reduce((a, b) => a + b, 0);
	return {
		count: samples.length,
		p50Ms: percentile(samples, 50),
		p99Ms: percentile(samples, 99),
		maxMs: samples.length ? Math.max(...samples) : 0,
		meanMs: samples.length ? sum / samples.length : 0,
	};
}

/** Collects the wall time of named operations. */
export class LatencyRecorder {
	private readonly samples = new Map<string, number[]>();

	async time<T>(name: string, run: () => Promise<T>): Promise<T> {
		const start = performance.now();
		try {
			return await run();
		} finally {
			this.record(name, performance.now() - start);
		}
	}

	record(name: string, ms: number): void {
		const list = this.samples.get(name) ?? [];
		list.push(ms);
		this.samples.set(name, list);
	}

	report(): Record<string, LatencySummary> {
		const out: Record<string, LatencySummary> = {};
		for (const [name, list] of this.samples) out[name] = summarize(list);
		return out;
	}
}

export interface MemorySample {
	heapUsedMb: number;
	rssMb: number;
}

/** Heap and resident set in MB, or null where `process.memoryUsage` does not exist (Workers, browsers). */
export function sampleMemory(): MemorySample | null {
	const proc = (globalThis as { process?: { memoryUsage?: () => NodeJS.MemoryUsage } }).process;
	if (!proc?.memoryUsage) return null;
	const m = proc.memoryUsage();
	return { heapUsedMb: m.heapUsed / 1_048_576, rssMb: m.rss / 1_048_576 };
}
