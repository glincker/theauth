import type { Simulator } from "../simulator/simulate.js";
import type { SimulateInput, SimulationDecision } from "../simulator/types.js";

export type ShadowDecision = SimulationDecision;

export interface ShadowDifference {
	/** Caller supplied label, e.g. the route. Keep personal data out of it. */
	label: string;
	incumbent: ShadowDecision | "error";
	theauth: ShadowDecision | "error";
}

export interface ShadowConfig<I> {
	incumbent: (input: I) => Promise<ShadowDecision>;
	theauth: (input: I) => Promise<ShadowDecision>;
	label: (input: I) => string;
	/** Called only when the two disagree. Errors are swallowed. */
	onDifference?: (diff: ShadowDifference) => void | Promise<void>;
	/** 0 to 1 share of calls that also run theauth. Default 1. */
	sampleRate?: number;
}

export interface ShadowResult {
	/** The incumbent's answer. This is the only decision a caller should act on. */
	decision: ShadowDecision;
	compared: boolean;
	differs: boolean;
}

/**
 * Run both systems, enforce only the incumbent. The theauth answer is compared and
 * reported, never returned as the decision, and its failures never reach the caller.
 */
export function createShadow<I>(config: ShadowConfig<I>) {
	const rate = config.sampleRate ?? 1;
	const counts = { compared: 0, differences: 0, errors: 0 };

	async function evaluate(input: I): Promise<ShadowResult> {
		const decision = await config.incumbent(input);
		if (rate < 1 && Math.random() >= rate) return { decision, compared: false, differs: false };
		let other: ShadowDecision | "error";
		try {
			other = await config.theauth(input);
		} catch {
			other = "error";
			counts.errors++;
		}
		counts.compared++;
		const differs = other !== decision;
		if (differs) {
			counts.differences++;
			try {
				await config.onDifference?.({
					label: config.label(input),
					incumbent: decision,
					theauth: other,
				});
			} catch {
				// Logging trouble must not affect the real decision.
			}
		}
		return { decision, compared: true, differs };
	}

	return { evaluate, stats: () => ({ ...counts }) };
}

/** Use theauth's simulator as the shadow side. It has no side effects. */
export function simulatorDecider<I>(
	simulator: Pick<Simulator, "simulate">,
	toInput: (input: I) => SimulateInput,
): (input: I) => Promise<ShadowDecision> {
	return async (input) => {
		const res = await simulator.simulate(toInput(input));
		if (!res.success) throw new Error(res.error.code);
		return res.data.decision;
	};
}
