// Provenance labels: tag values, read tags back, derive labels, and track
// tool outputs so they flow into the arguments of later tool calls.
//
// Labels are only as good as the host's tagging. Nothing here inspects a
// model. Objects are tagged in a WeakMap (same reference back, JSON unchanged).
// Primitives cannot be keys, so they are wrapped in TaintedValue.

import type { ProvenanceMap } from "./types.js";
import { CALL_LABELS_KEY } from "./types.js";

const MAX_DEPTH = 8;
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

function visit(value: unknown, into: Set<string>, depth: number, seen: Set<object>): void {
	if (value instanceof TaintedValue) {
		for (const l of value.labels) into.add(l);
		visit(value.value, into, depth + 1, seen);
		return;
	}
	if (value === null || typeof value !== "object") return;
	if (seen.has(value)) return;
	seen.add(value);
	for (const l of objectLabels.get(value) ?? []) into.add(l);
	if (depth >= MAX_DEPTH) return;
	const children = Array.isArray(value) ? value : Object.values(value);
	for (const child of children) visit(child, into, depth + 1, seen);
}

/** Labels carried by a value, including labels of anything nested inside it. */
export function labelsOf(value: unknown): string[] {
	const out = new Set<string>();
	visit(value, out, 0, new Set());
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
			visit(source, out, 0, new Set());
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
	for (const [arg, set] of out) result[arg] = [...set].sort();
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
}

/**
 * Remembers labels for tool outputs so they can flow into later calls. Objects are tagged
 * in place, strings are remembered by content. Loses nothing across JSON: a string the
 * model copies verbatim into an argument is still found.
 */
export class ProvenanceTracker {
	private readonly texts = new Map<string, Set<string>>();
	private readonly substringMatch: boolean;
	private readonly minTextLength: number;
	private readonly maxTextEntries: number;

	constructor(options: ProvenanceTrackerOptions = {}) {
		this.substringMatch = options.substringMatch ?? true;
		this.minTextLength = options.minTextLength ?? 4;
		this.maxTextEntries = options.maxTextEntries ?? 1000;
	}

	/** Register labels for a value (and the strings inside it). Returns the value. */
	track<T>(value: T, labels: LabelInput): T {
		const set = toSet(labels);
		if (set.size === 0) return value;
		if (value !== null && typeof value === "object" && !(value instanceof TaintedValue)) {
			tainted(value, [...set]);
		}
		this.rememberStrings(value, set, 0, new Set());
		return value;
	}

	/** Register a tool result as `tool_output:<tool>`, plus any labels it inherits. */
	trackResult<T>(toolName: string, result: T, inherited: readonly string[] = []): T {
		return this.track(result, [`tool_output:${toolName}`, ...inherited]);
	}

	/** Labels for a value: its own tags plus labels of tracked strings found in it. */
	labelsOf(value: unknown): string[] {
		const out = new Set(labelsOf(value));
		this.collectTexts(value, out, 0, new Set());
		return [...out];
	}

	/** Per-argument labels for an argument object. */
	argLabels(args: unknown): ProvenanceMap {
		const out: ProvenanceMap = {};
		if (args === null || typeof args !== "object") return out;
		for (const [name, value] of Object.entries(args)) {
			const labels = this.labelsOf(value);
			if (labels.length > 0) out[name] = labels;
		}
		const callLabels = labelsOf(args);
		if (callLabels.length > 0) out[CALL_LABELS_KEY] = callLabels;
		return out;
	}

	private rememberStrings(value: unknown, labels: Set<string>, depth: number, seen: Set<object>) {
		const raw = untaint(value);
		if (typeof raw === "string") {
			if (raw.length < this.minTextLength) return;
			const set = this.texts.get(raw) ?? new Set<string>();
			for (const l of labels) set.add(l);
			this.texts.delete(raw);
			this.texts.set(raw, set);
			while (this.texts.size > this.maxTextEntries) {
				const oldest = this.texts.keys().next().value;
				if (oldest === undefined) break;
				this.texts.delete(oldest);
			}
			return;
		}
		if (raw === null || typeof raw !== "object" || depth >= MAX_DEPTH || seen.has(raw)) return;
		seen.add(raw);
		const children = Array.isArray(raw) ? raw : Object.values(raw);
		for (const child of children) this.rememberStrings(child, labels, depth + 1, seen);
	}

	private collectTexts(value: unknown, into: Set<string>, depth: number, seen: Set<object>) {
		const raw = untaint(value);
		if (typeof raw === "string") {
			if (raw.length < this.minTextLength) return;
			const exact = this.texts.get(raw);
			if (exact) for (const l of exact) into.add(l);
			if (this.substringMatch) {
				for (const [text, labels] of this.texts) {
					if (text !== raw && text.includes(raw)) for (const l of labels) into.add(l);
				}
			}
			return;
		}
		if (raw === null || typeof raw !== "object" || depth >= MAX_DEPTH || seen.has(raw)) return;
		seen.add(raw);
		const children = Array.isArray(raw) ? raw : Object.values(raw);
		for (const child of children) this.collectTexts(child, into, depth + 1, seen);
	}
}
