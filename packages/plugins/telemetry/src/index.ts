export type { TelemetryConfig, TelemetryModule, TelemetrySpan } from "./exporter.js";
export { createTelemetryModule } from "./exporter.js";
export type {
	DecisionEventLike,
	OtelAttributes,
	OtelMeterLike,
	OtelSpanLike,
	OtelTracerLike,
	TheAuthOtel,
	TheAuthOtelOptions,
} from "./otel.js";
export { OTEL_NAMES, theauthOtel } from "./otel.js";
