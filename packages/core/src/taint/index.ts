export type { LabelInput, ProvenanceTrackerOptions } from "./labels.js";
export {
	deriveLabels,
	labelsOf,
	matchLabel,
	mergeProvenance,
	ProvenanceTracker,
	TaintedValue,
	tainted,
	untaint,
} from "./labels.js";
export type {
	ProvenanceMap,
	TaintConfig,
	TaintEffect,
	TaintLabelRule,
	TaintMatch,
	TaintRule,
	TaintVerdict,
} from "./types.js";
export { CALL_LABELS_KEY } from "./types.js";
