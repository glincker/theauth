import type {
	DecisionEvent,
	ObservabilityConfig,
	ObservabilityStats,
	TheAuthLogger,
} from "./types.js";

export type {
	DecisionEvent,
	DecisionHookOutcome,
	ObservabilityConfig,
	ObservabilityStats,
	TheAuthLogger,
} from "./types.js";

const NOOP = (): void => {};

/** Logger that drops everything. The default when `logger` is not configured. */
export const NOOP_LOGGER: TheAuthLogger = {
	debug: NOOP,
	info: NOOP,
	warn: NOOP,
	error: NOOP,
};

const REDACTED = "[redacted]";
const DEFAULT_SLOW_MS = 5;

function slowThreshold(config: ObservabilityConfig | undefined): number {
	if (config?.slowListenerMs !== undefined) return config.slowListenerMs;
	const raw =
		typeof process !== "undefined" ? process.env?.THEAUTH_OBSERVABILITY_SLOW_MS : undefined;
	const parsed = raw ? Number(raw) : Number.NaN;
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : DEFAULT_SLOW_MS;
}

/** Wrap a user logger so a throwing logger never reaches the library. */
function guardLogger(logger: TheAuthLogger): TheAuthLogger {
	const wrap =
		(fn: TheAuthLogger["debug"]): TheAuthLogger["debug"] =>
		(message, fields) => {
			try {
				fn.call(logger, message, fields);
			} catch {
				// A broken logger must not break authorization.
			}
		};
	return {
		debug: wrap(logger.debug),
		info: wrap(logger.info),
		warn: wrap(logger.warn),
		error: wrap(logger.error),
	};
}

export interface Observability {
	logger: TheAuthLogger;
	/** True when the app supplied a logger, so callers can keep a console fallback for startup warnings. */
	loggerConfigured: boolean;
	/** True when `onDecision` is set. Callers skip building the event when false. */
	enabled: boolean;
	/** Queue one event. The event is built lazily inside the microtask, so a slow field (delegation depth) never delays the caller. */
	emit(build: () => Promise<DecisionEvent> | DecisionEvent): void;
	stats(): ObservabilityStats;
}

/**
 * Observability runtime: the guarded logger and the decision event dispatcher.
 *
 * Overhead on the authorize path with `onDecision` set is one closure allocation and one
 * `queueMicrotask`. Without it, `emit` is not called at all (`enabled` is false).
 */
export function createObservability(
	config: ObservabilityConfig | undefined,
	logger: TheAuthLogger | undefined,
): Observability {
	const safeLogger = logger ? guardLogger(logger) : NOOP_LOGGER;
	const listener = config?.onDecision;
	const redact = config?.redactResource;
	const slowMs = slowThreshold(config);
	const counters: ObservabilityStats = { emitted: 0, errors: 0, slow: 0 };

	function fail(error: unknown): void {
		counters.errors += 1;
		safeLogger.warn("observability.onDecision failed", {
			error: error instanceof Error ? error.message : String(error),
		});
	}

	function applyRedaction(event: DecisionEvent): DecisionEvent {
		if (!redact) return event;
		try {
			return { ...event, resource: redact(event.resource) };
		} catch {
			return { ...event, resource: REDACTED };
		}
	}

	async function deliver(
		build: () => Promise<DecisionEvent> | DecisionEvent,
		fn: (event: DecisionEvent) => void,
	): Promise<void> {
		try {
			const event = applyRedaction(await build());
			counters.emitted += 1;
			const start = performance.now();
			const returned: unknown = fn(event);
			if (returned instanceof Promise) returned.catch(fail);
			if (performance.now() - start > slowMs) {
				counters.slow += 1;
				safeLogger.warn("observability.onDecision was slow", { thresholdMs: slowMs });
			}
		} catch (error) {
			fail(error);
		}
	}

	return {
		logger: safeLogger,
		loggerConfigured: logger !== undefined,
		enabled: listener !== undefined,
		emit(build) {
			if (!listener) return;
			queueMicrotask(() => {
				void deliver(build, listener);
			});
		},
		stats: () => ({ ...counters }),
	};
}
