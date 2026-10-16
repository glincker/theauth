// Provenance labels: tag values, read tags back, derive labels, and track
// tool outputs so they flow into the arguments of later tool calls.
//
// Labels are only as good as the host's tagging. Nothing here inspects a
// model. Objects are tagged in a WeakMap (same reference back, JSON unchanged).
// Primitives cannot be keys, so they are wrapped in TaintedValue.

import { compareStrings } from "../internal-compare.js";
import type { ProvenanceMap } from "./types.js";
import { CALL_LABELS_KEY } from "./types.js";

/** Deepest nesting the walkers follow. Past it the walk stops and the value is marked unverified. */
const MAX_DEPTH = 64;
/** Most nodes (objects, arrays and leaves) one walk visits before it stops and marks the value unverified. */
const MAX_NODES = 250_000;
/**
 * Label added when a value is too deep or too large to scan in full. A rule that forbids
 * `unverified:*` (or `*`), or that requires a label, then acts on it: nothing hidden deep
 * inside a value can slip past a taint rule.
 */
export const UNVERIFIED_DEPTH_LABEL = "unverified:depth";
const objectLabels = new WeakMap<object, ReadonlySet<string>>();

/** Wrapper for a tagged primitive. JSON.stringify drops the labels on purpose. */
export class TaintedValue<T> {
	readonly value: T;
	readonly labels: readonly string[];
	constructor(value: T, labels: readonly string[]) {
		this.value = value;
		this.labels = Object.freeze([...labels]);
	}
	toJSON(): T {
		return this.value;
	}
	valueOf(): T {
		return this.value;
	}
}

export type LabelInput = string | readonly string[];
type Primitive = string | number | boolean | bigint | null | undefined;

function toSet(labels: LabelInput): Set<string> {
	const list = typeof labels === "string" ? [labels] : labels;
	return new Set(list.filter((l): l is string => typeof l === "string" && l.length > 0));
}

/**
 * Tag a value with labels. An object is tagged in place (the same reference is returned,
 * labels merge with any it already had). A primitive is returned as a TaintedValue.
 */
export function tainted<T extends object>(value: T, labels: LabelInput): T;
export function tainted<T extends Primitive>(value: T, labels: LabelInput): TaintedValue<T>;
export function tainted(value: unknown, labels: LabelInput): unknown {
	const add = toSet(labels);
	if (value instanceof TaintedValue) {
		return new TaintedValue(value.value, [...new Set([...value.labels, ...add])]);
	}
	if (value !== null && typeof value === "object") {
		const merged = new Set([...(objectLabels.get(value) ?? []), ...add]);
		objectLabels.set(value, merged);
		return value;
	}
	return new TaintedValue(value, [...add]);
}

/** Unwrap a TaintedValue. Any other value is returned as is. */
export function untaint<T>(value: T | TaintedValue<T>): T {
	return value instanceof TaintedValue ? value.value : value;
}

/** Set an own data property, safe for keys like "__proto__" that a plain assignment would swallow. */
export function setOwn<T>(target: Record<string, T>, key: string, value: T): void {
	Object.defineProperty(target, key, {
		value,
		enumerable: true,
		writable: true,
		configurable: true,
	});
}

/**
 * Walk a value with an explicit stack (no recursion, so depth cannot overflow the call
 * stack). Calls `visit` for every node once. Returns true when the walk was cut short by
 * the depth limit or the node budget, so the caller can fail closed.
 */
function walk(root: unknown, visit: (node: unknown) => void): boolean {
	const seen = new Set<object>();
	const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
	let nodes = 0;
	let truncated = false;
	for (let item = stack.pop(); item !== undefined; item = stack.pop()) {
		if (++nodes > MAX_NODES) return true;
		const { value, depth } = item;
		if (value instanceof TaintedValue) {
			visit(value);
			stack.push({ value: value.value, depth: depth + 1 });
			continue;
		}
		if (value === null || typeof value !== "object") {
			visit(value);
			continue;
		}
		if (seen.has(value)) continue;
		seen.add(value);
		visit(value);
		const children: unknown[] = Array.isArray(value) ? value : Object.values(value);
		if (children.length === 0) continue;
		if (depth >= MAX_DEPTH) {
			truncated = true;
			continue;
		}
		for (let i = children.length - 1; i >= 0; i--) {
			stack.push({ value: children[i], depth: depth + 1 });
		}
	}
	return truncated;
}

function collectLabels(value: unknown, into: Set<string>): void {
	const cut = walk(value, (node) => {
		if (node instanceof TaintedValue) {
			for (const l of node.labels) into.add(l);
		} else if (node !== null && typeof node === "object") {
			for (const l of objectLabels.get(node) ?? []) into.add(l);
		}
	});
	if (cut) into.add(UNVERIFIED_DEPTH_LABEL);
}

/**
 * Labels carried by a value, including labels of anything nested inside it. A value too
 * deep or too large to scan in full also carries `unverified:depth`.
 */
export function labelsOf(value: unknown): string[] {
	const out = new Set<string>();
	collectLabels(value, out);
	return [...out];
}

/**
 * Union of labels. A string array is read as a list of labels. Anything else is
 * read as a value (see labelsOf). A derived value is as sensitive as its most
 * sensitive source, so the union is the safe default.
 */
export function deriveLabels(...sources: unknown[]): string[] {
	const out = new Set<string>();
	for (const source of sources) {
		if (Array.isArray(source) && source.every((s) => typeof s === "string")) {
			for (const l of source as string[]) if (l) out.add(l);
		} else {
			collectLabels(source, out);
		}
	}
	return [...out];
}

/** Label match. `*` matches anything and a trailing `*` is a prefix wildcard ("tool_output:*"). */
export function matchLabel(pattern: string, label: string): boolean {
	if (pattern === "*") return true;
	if (pattern.endsWith("*")) return label.startsWith(pattern.slice(0, -1));
	return pattern === label;
}

/** Merge several ProvenanceMaps into one, unioning labels per key. */
export function mergeProvenance(...maps: Array<ProvenanceMap | undefined>): ProvenanceMap {
	const out = new Map<string, Set<string>>();
	for (const map of maps) {
		if (!map) continue;
		for (const [arg, labels] of Object.entries(map)) {
			const set = out.get(arg) ?? new Set<string>();
			for (const l of labels) if (l) set.add(l);
			if (set.size > 0) out.set(arg, set);
		}
	}
	const result: ProvenanceMap = {};
	for (const [arg, set] of out) setOwn(result, arg, [...set].sort(compareStrings));
	return result;
}

export interface ProvenanceTrackerOptions {
	/**
	 * Also match an argument string that appears inside a tracked string (for example an
	 * address lifted out of a fetched page). Heuristic. Default true.
	 */
	substringMatch?: boolean;
	/** Shortest string the tracker will remember or match by substring. Default 4. */
	minTextLength?: number;
	/** Most tracked strings kept, oldest dropped first. Default 1000. */
	maxTextEntries?: number;
	/**
	 * Total size of tracked strings kept, in UTF-16 code units (about bytes for ASCII), oldest
	 * dropped first. A single string larger than this is kept as its first `maxTextBytes`
	 * code units only. Default 1048576 (1 MiB).
	 */
	maxTextBytes?: number;
	/**
	 * Longest argument string that is searched for inside tracked strings. Longer ones are
	 * matched against whole tracked strings only. Default 65536.
	 */
	maxSubstringLength?: number;
}

function positiveInt(value: number | undefined, fallback: number): number {
	return typeof value === "number" && Number.isFinite(value) && value >= 1
		? Math.floor(value)
		: fallback;
}

/**
 * Remembers labels for tool outputs so they can flow into later calls. Objects are tagged
 * in place, strings are remembered by content. Loses nothing across JSON: a string the
 * model copies verbatim into an argument is still found.
 */
export class ProvenanceTracker {
	private readonly texts = new Map<string, Set<string>>();
	private textBytes = 0;
	private readonly substringMatch: boolean;
	private readonly minTextLength: number;
	private readonly maxTextEntries: number;
	private readonly maxTextBytes: number;
	private readonly maxSubstringLength: number;

	constructor(options: ProvenanceTrackerOptions = {}) {
		this.substringMatch = options.substringMatch ?? true;
		const minText = options.minTextLength;
		this.minTextLength =
			typeof minText === "number" && Number.isFinite(minText) && minText >= 0
				? Math.floor(minText)
				: 4;
		this.maxTextEntries = positiveInt(options.maxTextEntries, 1000);
		this.maxTextBytes = positiveInt(options.maxTextBytes, 1_048_576);
		this.maxSubstringLength = positiveInt(options.maxSubstringLength, 65_536);
	}

	/** Register labels for a value (and the strings inside it). Returns the value. */
	track<T>(value: T, labels: LabelInput): T {
		const set = toSet(labels);
		if (set.size === 0) return value;
		if (value !== null && typeof value === "object" && !(value instanceof TaintedValue)) {
			tainted(value, [...set]);
		}
		walk(value, (node) => {
			const raw = untaint(node);
			if (typeof raw === "string") this.remember(raw, set);
		});
		return value;
	}

	/** Register a tool result as `tool_output:<tool>`, plus any labels it inherits. */
	trackResult<T>(toolName: string, result: T, inherited: readonly string[] = []): T {
		return this.track(result, [`tool_output:${toolName}`, ...inherited]);
	}

	/** Labels for a value: its own tags plus labels of tracked strings found in it. */
	labelsOf(value: unknown): string[] {
		const out = new Set<string>();
		collectLabels(value, out);
		const cut = walk(value, (node) => {
			const raw = untaint(node);
			if (typeof raw === "string") this.collectText(raw, out);
		});
		if (cut) out.add(UNVERIFIED_DEPTH_LABEL);
		return [...out];
	}

	/** Per-argument labels for an argument object. */
	argLabels(args: unknown): ProvenanceMap {
		const out: ProvenanceMap = {};
		if (args === null || typeof args !== "object") return out;
		for (const [name, value] of Object.entries(args)) {
			const labels = this.labelsOf(value);
			if (labels.length > 0) setOwn(out, name, labels);
		}
		const callLabels = labelsOf(args);
		if (callLabels.length > 0) out[CALL_LABELS_KEY] = callLabels;
		return out;
	}

	private remember(text: string, labels: Set<string>): void {
		if (text.length < this.minTextLength) return;
		const raw = text.length > this.maxTextBytes ? text.slice(0, this.maxTextBytes) : text;
		const existing = this.texts.get(raw);
		const set = existing ?? new Set<string>();
		for (const l of labels) set.add(l);
		if (existing) this.textBytes -= raw.length;
		this.texts.delete(raw);
		this.texts.set(raw, set);
		this.textBytes += raw.length;
		while (this.texts.size > this.maxTextEntries || this.textBytes > this.maxTextBytes) {
			const oldest = this.texts.keys().next().value;
			if (oldest === undefined) break;
			this.texts.delete(oldest);
			this.textBytes -= oldest.length;
		}
	}

	private collectText(raw: string, into: Set<string>): void {
		if (raw.length < this.minTextLength) return;
		const exact = this.texts.get(raw);
		if (exact) for (const l of exact) into.add(l);
		if (this.substringMatch && raw.length <= this.maxSubstringLength) {
			for (const [text, labels] of this.texts) {
				if (text !== raw && text.includes(raw)) for (const l of labels) into.add(l);
			}
		}
	}
}
