/**
 * OpenTelemetry mapping for TheAuth decision events.
 *
 * Structural types only: `@opentelemetry/api`'s `Tracer` and `Meter` satisfy them as is, so there is
 * no OpenTelemetry dependency here. There is no standard semantic convention for authorization
 * decisions, so everything lives under the `theauth.` namespace and follows the OTel naming rules
 * (lowercase, dot separated, units in the instrument, low cardinality on metrics).
 */

export type OtelAttributeValue = string | number | boolean;
export type OtelAttributes = Record<string, OtelAttributeValue>;

/** Subset of `@opentelemetry/api` Span. */
export interface OtelSpanLike {
	addEvent(name: string, attributes?: OtelAttributes, time?: number | Date): unknown;
	setStatus(status: { code: number; message?: string }): unknown;
	end(endTime?: number | Date): void;
}

/** Subset of `@opentelemetry/api` Tracer. */
export interface OtelTracerLike {
	startSpan(
		name: string,
		options?: { startTime?: number | Date; attributes?: OtelAttributes },
	): OtelSpanLike;
}

/** Subset of `@opentelemetry/api` Meter. */
export interface OtelMeterLike {
	createCounter(
		name: string,
		options?: { description?: string; unit?: string },
	): { add(value: number, attributes?: OtelAttributes): void };
	createHistogram(
		name: string,
		options?: { description?: string; unit?: string },
	): { record(value: number, attributes?: OtelAttributes): void };
}

/** The fields of core's `DecisionEvent` this mapping reads. Core's type is assignable to it. */
export interface DecisionEventLike {
	source: string;
	agentId?: string;
	ownerId?: string;
	action: string;
	resource: string;
	decision: "allow" | "deny" | "escalate";
	code: string;
	durationMs: number;
	cacheHit: boolean;
	delegationDepth: number;
	hookOutcome?: "allow" | "deny" | "escalate" | "timeout" | "error" | "fail_open";
	hookMs?: number;
	guard?: string;
	auditId: string;
	at: Date;
}

export interface TheAuthOtelOptions {
	tracer?: OtelTracerLike;
	meter?: OtelMeterLike;
	/** Put the resource string on spans as `theauth.resource`. Default true. Metrics never carry it. Pair with core's `observability.redactResource` when resources hold identifiers. */
	includeResource?: boolean;
}

export interface TheAuthOtel {
	/** Spread into the TheAuth config: `createTheAuth({ ...theauthOtel({ tracer, meter }) })`. */
	observability: { onDecision: (event: DecisionEventLike) => void };
}

/** Instrument names, exported so dashboards and alerts do not retype them. */
export const OTEL_NAMES = {
	decisionsCounter: "theauth.decisions",
	durationHistogram: "theauth.decision.duration",
	authorizeSpan: "theauth.authorize",
	policySpan: "theauth.policy.evaluate",
	hookTimeoutEvent: "theauth.hook.timeout",
	hookErrorEvent: "theauth.hook.error",
	hookFailOpenEvent: "theauth.hook.fail_open",
} as const;

/** OTel `SpanStatusCode.ERROR`. Inlined to stay dependency free. */
const STATUS_ERROR = 2;

const HOOK_EVENTS: Partial<Record<NonNullable<DecisionEventLike["hookOutcome"]>, string>> = {
	timeout: OTEL_NAMES.hookTimeoutEvent,
	error: OTEL_NAMES.hookErrorEvent,
	fail_open: OTEL_NAMES.hookFailOpenEvent,
};

function spanAttributes(event: DecisionEventLike, includeResource: boolean): OtelAttributes {
	const attributes: OtelAttributes = {
		"theauth.source": event.source,
		"theauth.action": event.action,
		"theauth.decision": event.decision,
		"theauth.decision.code": event.code,
		"theauth.delegation.depth": event.delegationDepth,
		"theauth.cache_hit": event.cacheHit,
	};
	if (event.agentId) attributes["theauth.agent.id"] = event.agentId;
	if (event.ownerId) attributes["theauth.owner.id"] = event.ownerId;
	if (includeResource) attributes["theauth.resource"] = event.resource;
	if (event.auditId) attributes["theauth.audit.id"] = event.auditId;
	if (event.guard) attributes["theauth.guard.name"] = event.guard;
	if (event.hookOutcome) attributes["theauth.hook.outcome"] = event.hookOutcome;
	if (event.hookMs !== undefined) attributes["theauth.hook.duration"] = event.hookMs;
	return attributes;
}

/**
 * Map decision events to spans and metrics.
 *
 * - Span `theauth.authorize` (`theauth.policy.evaluate` for policy.evaluate), backdated to cover the decision.
 *   Attributes: `theauth.decision`, `theauth.decision.code`, `theauth.agent.id`, `theauth.delegation.depth`,
 *   `theauth.guard.name`, `theauth.source`, `theauth.hook.outcome`, `theauth.hook.duration` (ms).
 *   Span events `theauth.hook.timeout`, `theauth.hook.error`, `theauth.hook.fail_open`. A hook timeout or error sets the span status to ERROR; a deny does not, because a denial is a correct answer.
 * - Counter `theauth.decisions` with attributes `theauth.decision`, `theauth.decision.code`, `theauth.source`.
 * - Histogram `theauth.decision.duration` (unit `ms`), same attributes.
 *
 * Metric attributes stay low cardinality: no agent id, no resource, no action.
 */
export function theauthOtel(options: TheAuthOtelOptions = {}): TheAuthOtel {
	const { tracer, meter } = options;
	const includeResource = options.includeResource ?? true;
	const decisions = meter?.createCounter(OTEL_NAMES.decisionsCounter, {
		description: "Authorization decisions by outcome and decision code",
		unit: "{decision}",
	});
	const duration = meter?.createHistogram(OTEL_NAMES.durationHistogram, {
		description: "Wall time of an authorization decision, hook included",
		unit: "ms",
	});

	function onDecision(event: DecisionEventLike): void {
		const metricAttributes: OtelAttributes = {
			"theauth.decision": event.decision,
			"theauth.decision.code": event.code,
			"theauth.source": event.source,
		};
		decisions?.add(1, metricAttributes);
		duration?.record(event.durationMs, metricAttributes);
		if (!tracer) return;

		const endTime = event.at;
		const span = tracer.startSpan(
			event.source === "policy.evaluate" ? OTEL_NAMES.policySpan : OTEL_NAMES.authorizeSpan,
			{
				startTime: new Date(endTime.getTime() - event.durationMs),
				attributes: spanAttributes(event, includeResource),
			},
		);
		const hookEvent = event.hookOutcome ? HOOK_EVENTS[event.hookOutcome] : undefined;
		if (hookEvent) {
			span.addEvent(
				hookEvent,
				{
					"theauth.decision.code": event.code,
					...(event.hookMs !== undefined ? { "theauth.hook.duration": event.hookMs } : {}),
					...(event.guard ? { "theauth.guard.name": event.guard } : {}),
				},
				endTime,
			);
			if (event.hookOutcome !== "fail_open") {
				span.setStatus({
					code: STATUS_ERROR,
					message: `beforeAuthorize hook ${event.hookOutcome}`,
				});
			}
		}
		span.end(endTime);
	}

	return { observability: { onDecision } };
}
