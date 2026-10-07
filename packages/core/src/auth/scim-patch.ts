/**
 * SCIM 2.0 PATCH operation engine (RFC 7644 §3.5.2).
 *
 * Parses PATCH path expressions of the form:
 *
 *   PATH = attrPath [ "[" valFilter "]" ] [ "." attrPath ]
 *
 * Examples:
 *   displayName
 *   name.givenName
 *   emails
 *   emails[type eq "work"]
 *   emails[type eq "work"].value
 *   urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department
 *
 * The engine mutates a plain JS object representing a SCIM resource.
 * Downstream code maps the mutated object back to the database row.
 *
 * Security posture:
 *
 *  - Reject unknown operation types — only add/replace/remove per §3.5.2.
 *  - Reject mutation of immutable attributes (id, meta.created, schemas)
 *    with `scimType=mutability` errors.
 *  - Cap the number of operations per request to defend against
 *    request-amplification DoS; caller passes the cap.
 *  - Never evaluate user-provided code — the path parser and the filter
 *    evaluator are both pure AST walkers.
 */

import type { FilterAst } from "./scim-filter.js";
import { evaluateFilter, parseFilter, ScimFilterError } from "./scim-filter.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PatchOpKind = "add" | "replace" | "remove";

export interface PatchOperation {
	op: PatchOpKind;
	path?: string;
	value?: unknown;
}

export interface PatchPath {
	/** Optional URN prefix (for extension schemas). */
	schemaUrn?: string;
	/** Base attribute name (required). */
	base: string;
	/** Optional value-filter expression that selects elements of a multi-valued attribute. */
	valueFilter?: FilterAst;
	/** Optional sub-attribute path after the value filter or the base. */
	subPath?: string[];
}

export class ScimPatchError extends Error {
	public readonly scimType: string;
	public readonly status: number;
	constructor(message: string, scimType: string, status = 400) {
		super(message);
		this.name = "ScimPatchError";
		this.scimType = scimType;
		this.status = status;
	}
}

/** Attributes the client cannot PATCH under any circumstance. RFC 7643 §7. */
const IMMUTABLE_PATHS = new Set<string>([
	"id",
	"schemas",
	"meta",
	"meta.created",
	"meta.lastmodified",
	"meta.location",
	"meta.resourcetype",
]);

// ---------------------------------------------------------------------------
// Path parser
// ---------------------------------------------------------------------------

/**
 * Parse a PATCH path expression into the structured form.
 *
 * @throws ScimPatchError on malformed input.
 */
export function parsePatchPath(raw: string): PatchPath {
	if (raw.length === 0) {
		throw new ScimPatchError("Empty PATCH path", "invalidPath");
	}

	// Split on the first '[' to separate attr vs value filter.
	const bracketIdx = raw.indexOf("[");

	// No value filter — simple dotted path.
	if (bracketIdx === -1) {
		const { schemaUrn, parts } = splitSchemaUrn(raw);
		if (parts.length === 0) throw new ScimPatchError("Empty PATCH path", "invalidPath");
		return {
			schemaUrn,
			base: parts[0] as string,
			subPath: parts.length > 1 ? parts.slice(1) : undefined,
		};
	}

	// attr[filter](.sub)?
	const closeIdx = raw.lastIndexOf("]");
	if (closeIdx < bracketIdx) {
		throw new ScimPatchError("Unbalanced brackets in PATCH path", "invalidPath");
	}

	const headRaw = raw.slice(0, bracketIdx);
	const filterRaw = raw.slice(bracketIdx + 1, closeIdx);
	const tailRaw = raw.slice(closeIdx + 1);

	const { schemaUrn, parts: headParts } = splitSchemaUrn(headRaw);
	if (headParts.length === 0) {
		throw new ScimPatchError("PATCH path missing attribute before '['", "invalidPath");
	}
	if (headParts.length > 1) {
		throw new ScimPatchError(
			"PATCH value-filter must attach to a top-level attribute",
			"invalidPath",
		);
	}

	let valueFilter: FilterAst;
	try {
		valueFilter = parseFilter(filterRaw);
	} catch (err) {
		if (err instanceof ScimFilterError) {
			throw new ScimPatchError(`Invalid value filter: ${err.message}`, "invalidPath");
		}
		throw err;
	}

	let subPath: string[] | undefined;
	if (tailRaw.length > 0) {
		if (!tailRaw.startsWith(".")) {
			throw new ScimPatchError(
				`Unexpected characters after value filter: "${tailRaw}"`,
				"invalidPath",
			);
		}
		subPath = tailRaw
			.slice(1)
			.split(".")
			.filter((p) => p.length > 0);
		if (subPath.length === 0) {
			throw new ScimPatchError("Trailing '.' in PATCH path", "invalidPath");
		}
	}

	return { schemaUrn, base: headParts[0] as string, valueFilter, subPath };
}

function splitSchemaUrn(raw: string): { schemaUrn?: string; parts: string[] } {
	if (!raw.startsWith("urn:")) {
		return { parts: raw.split(".").filter((p) => p.length > 0) };
	}
	const colonIndex = raw.lastIndexOf(":");
	if (colonIndex < 4) return { parts: raw.split(".").filter((p) => p.length > 0) };
	const schemaUrn = raw.slice(0, colonIndex);
	const tail = raw.slice(colonIndex + 1);
	return { schemaUrn, parts: tail.split(".").filter((p) => p.length > 0) };
}

// ---------------------------------------------------------------------------
// Operation applicator
// ---------------------------------------------------------------------------

export interface ApplyPatchOptions {
	/** Maximum number of operations. Default 1000. Exceeding this throws `tooMany`. */
	maxOperations?: number;
	/**
	 * Extra paths to reject. Base reserved list already covers `id`, `schemas`,
	 * `meta`, etc. Pass lower-cased dotted paths.
	 */
	readonlyPaths?: string[];
}

type MutableResource = Record<string, unknown>;

/**
 * Apply a list of PATCH operations to a resource in place.
 *
 * Mutates `resource`. Return value is the same reference, for chaining.
 *
 * @throws ScimPatchError on unknown ops, invalid paths, mutability violations,
 *         or operation-count overrun.
 */
export function applyPatchOps(
	resource: MutableResource,
	operations: PatchOperation[],
	options: ApplyPatchOptions = {},
): MutableResource {
	const cap = options.maxOperations ?? 1000;
	if (operations.length > cap) {
		throw new ScimPatchError(
			`PATCH has ${operations.length} operations, limit is ${cap}`,
			"tooMany",
			413,
		);
	}

	const extraReadonly = new Set((options.readonlyPaths ?? []).map((p) => p.toLowerCase()));

	for (const rawOp of operations) {
		const op = rawOp.op?.toLowerCase() as PatchOpKind | undefined;
		if (op !== "add" && op !== "replace" && op !== "remove") {
			throw new ScimPatchError(`Unknown PATCH op "${rawOp.op}"`, "invalidValue");
		}

		if (!rawOp.path) {
			// No path — value is a partial object merged into the resource root.
			if (op === "remove") {
				throw new ScimPatchError("PATCH remove requires a path", "noTarget");
			}
			if (rawOp.value === undefined || rawOp.value === null) continue;
			if (typeof rawOp.value !== "object") {
				throw new ScimPatchError(
					"PATCH value must be an object when path is absent",
					"invalidValue",
				);
			}
			mergeInto(resource, rawOp.value as MutableResource, op, extraReadonly);
			continue;
		}

		let path: PatchPath;
		try {
			path = parsePatchPath(rawOp.path);
		} catch (err) {
			if (err instanceof ScimPatchError) throw err;
			throw new ScimPatchError(`Invalid PATCH path "${rawOp.path}"`, "invalidPath");
		}

		const joinedPath = joinPath(path);
		if (IMMUTABLE_PATHS.has(joinedPath) || extraReadonly.has(joinedPath)) {
			throw new ScimPatchError(`Attribute "${joinedPath}" is immutable`, "mutability");
		}

		applyToResource(resource, path, op, rawOp.value);
	}

	return resource;
}

function joinPath(path: PatchPath): string {
	const head = path.schemaUrn ? `${path.schemaUrn}:${path.base}` : path.base;
	const sub = path.subPath && path.subPath.length > 0 ? `.${path.subPath.join(".")}` : "";
	return `${head}${sub}`.toLowerCase();
}

function containerFor(resource: MutableResource, schemaUrn?: string): MutableResource {
	if (!schemaUrn) return resource;
	const existing = resource[schemaUrn];
	if (existing && typeof existing === "object" && !Array.isArray(existing)) {
		return existing as MutableResource;
	}
	const next: MutableResource = {};
	resource[schemaUrn] = next;
	return next;
}

function mergeInto(
	target: MutableResource,
	source: MutableResource,
	op: PatchOpKind,
	readonlyPaths: Set<string>,
): void {
	for (const [key, value] of Object.entries(source)) {
		const lower = key.toLowerCase();
		if (IMMUTABLE_PATHS.has(lower) || readonlyPaths.has(lower)) {
			throw new ScimPatchError(`Attribute "${key}" is immutable`, "mutability");
		}
		if (op === "add" && Array.isArray(target[key]) && Array.isArray(value)) {
			target[key] = (target[key] as unknown[]).concat(value);
			continue;
		}
		target[key] = value;
	}
}

function applyToResource(
	resource: MutableResource,
	path: PatchPath,
	op: PatchOpKind,
	value: unknown,
): void {
	const container = containerFor(resource, path.schemaUrn);
	const currentBase = container[path.base];

	if (path.valueFilter) {
		if (!Array.isArray(currentBase)) {
			throw new ScimPatchError(
				`Value filter requires "${path.base}" to be an array`,
				"invalidPath",
			);
		}
		const arr = currentBase as MutableResource[];
		if (op === "remove") {
			container[path.base] = arr.filter(
				(item) => !evaluateFilter(path.valueFilter as FilterAst, item),
			);
			return;
		}
		// add / replace — apply `value` to each matching element.
		for (const item of arr) {
			if (!evaluateFilter(path.valueFilter as FilterAst, item)) continue;
			if (path.subPath && path.subPath.length > 0) {
				setDeep(item, path.subPath, value);
			} else if (value && typeof value === "object" && !Array.isArray(value)) {
				mergeInto(item, value as MutableResource, op, new Set<string>());
			} else {
				throw new ScimPatchError(
					"Value filter without subPath requires object value",
					"invalidValue",
				);
			}
		}
		return;
	}

	// No value filter — simple add/replace/remove.
	if (op === "remove") {
		if (path.subPath && path.subPath.length > 0) {
			deleteDeep(currentBase, path.subPath);
		} else {
			container[path.base] = undefined;
		}
		return;
	}

	if (path.subPath && path.subPath.length > 0) {
		const host = ensureObject(container, path.base);
		setDeep(host, path.subPath, value);
		return;
	}

	if (op === "add" && Array.isArray(currentBase) && Array.isArray(value)) {
		container[path.base] = currentBase.concat(value);
		return;
	}

	container[path.base] = value;
}

function ensureObject(container: MutableResource, key: string): MutableResource {
	const current = container[key];
	if (current && typeof current === "object" && !Array.isArray(current)) {
		return current as MutableResource;
	}
	const next: MutableResource = {};
	container[key] = next;
	return next;
}

function setDeep(target: unknown, path: string[], value: unknown): void {
	if (!target || typeof target !== "object") return;
	let cursor = target as MutableResource;
	for (let i = 0; i < path.length - 1; i += 1) {
		const segment = path[i] as string;
		const next = cursor[segment];
		if (next && typeof next === "object" && !Array.isArray(next)) {
			cursor = next as MutableResource;
		} else {
			const fresh: MutableResource = {};
			cursor[segment] = fresh;
			cursor = fresh;
		}
	}
	cursor[path[path.length - 1] as string] = value;
}

function deleteDeep(target: unknown, path: string[]): void {
	if (!target || typeof target !== "object") return;
	let cursor = target as MutableResource;
	for (let i = 0; i < path.length - 1; i += 1) {
		const segment = path[i] as string;
		const next = cursor[segment];
		if (!next || typeof next !== "object") return;
		cursor = next as MutableResource;
	}
	cursor[path[path.length - 1] as string] = undefined;
}
