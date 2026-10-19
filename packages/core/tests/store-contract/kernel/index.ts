import { describe } from "vitest";
import { defineAudit } from "./audit.js";
import { defineKernelOps } from "./kernel-ops.js";
import { defineRoundTrip } from "./round-trip.js";
import { defineSingleUse } from "./single-use.js";
import type { MakeTarget, SuiteOptions } from "./target.js";

export type { KernelTarget, MakeTarget, SuiteOptions } from "./target.js";

/**
 * The kernel and repository contract on one backend: every kernel primitive, value round trips,
 * the single-use repositories and the audit repository. `make` returns a fresh target each call,
 * all pointing at one database. Call it from a vitest file.
 */
export function runKernelContract(
	name: string,
	make: MakeTarget,
	options: SuiteOptions & { skip?: boolean; timeoutMs?: number } = {},
): void {
	const run = options.skip ? describe.skip : describe;
	run(`kernel contract: ${name}`, { timeout: options.timeoutMs ?? 120_000 }, () => {
		defineKernelOps(make, options);
		defineRoundTrip(make);
		defineSingleUse(make, options);
		defineAudit(make, options);
	});
}
