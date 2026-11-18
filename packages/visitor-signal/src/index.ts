export { canonicalise } from "./canonical.js";
export { collect, collectSignalV1, findUnavailable } from "./collector.js";
export { computeConfidence, DEFAULT_CONFIDENCE_MODEL } from "./confidence.js";
export type { ConsentDecision } from "./consent.js";
export { evaluateConsent, isDntSet } from "./consent.js";
export { DEFAULTS } from "./defaults.js";
export type { ValidationResult } from "./schema.js";
export { validatePayload } from "./schema.js";
export { toSignalV1 } from "./signal-v1.js";
export { buildCaps, CAP_BITS } from "./sources/capabilities.js";
export { bucketCores, bucketMemory } from "./sources/hardware.js";
export { bucketScreen } from "./sources/screen.js";
export type {
	CollectOptions,
	Components,
	ConfidenceModel,
	ConsentHook,
	ConsentState,
	Flags,
	Mode,
	Result,
	SignalV1,
	Status,
	SuppressedReason,
	UnavailableName,
	VisitorSignalPayload,
} from "./types.js";
