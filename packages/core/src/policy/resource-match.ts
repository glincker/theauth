/**
 * Resource pattern matching, in two modes.
 *
 * `colon` (the default, unchanged since 1.0): resources are `:` separated. A pattern segment that is exactly `*`
 * matches that segment and everything after it. Nothing else is a wildcard, so `ros2:/fleet/*` is literal text.
 *
 * `path` (opt in with `resourceMatching: "path"`): the colon rules above still apply, and inside one colon segment
 * `/` separates path segments. A path segment that is exactly `*` matches one segment, `**` matches one or more.
 * Wildcards never match an empty, `.` or `..` segment (so a traversal such as `/fleet/a/../../admin` cannot ride a
 * glob), never cross a `:`, and a partial glob such as `r*` is literal. A whole colon segment `*` as the LAST
 * pattern segment keeps its legacy meaning (it matches the rest). Before the last segment it matches exactly one
 * non-empty segment, unlike the default where `a:*:b` also grants `a:x:anything` (the opt in mode fixes that surprise). No MQTT `+` or `#` aliases: design D8 maps topic levels to colon segments and
 * says `+` has no equivalent. Matching is case sensitive and does not decode percent escapes.
 *
 * Every decision in the library goes through `matchResource`, so the default path must stay byte for byte the
 * original. The path logic lives in its own function and only runs when the mode is `path`.
 */

export type ResourceMatching = "colon" | "path";

export const RESOURCE_MATCHING_MODES: readonly ResourceMatching[] = ["colon", "path"];

/** Read an untrusted mode value. Anything but the exact string `path` is the default. */
export function resolveResourceMatching(value: unknown): ResourceMatching {
	return value === "path" ? "path" : "colon";
}

/**
 * Legacy matcher, the default for every authorization decision. Same answers as the original split based code (pinned by tests/perf-equivalence.test.ts), without splitting either string: it walks both with `indexOf`, so a miss on the first segment costs no allocation. The permission scan calls this once per permission, so allocations here multiply.
 */
export function matchColonResource(pattern: string, resource: string): boolean {
	if (pattern === "*") return true;

	let pi = 0;
	let ri = 0;
	for (;;) {
		const pe = pattern.indexOf(":", pi);
		const pEnd = pe === -1 ? pattern.length : pe;
		// A pattern segment that is exactly `*` matches this segment and everything after it.
		if (pEnd - pi === 1 && pattern.charCodeAt(pi) === 42) return true;
		// The resource has fewer segments than the pattern.
		if (ri > resource.length) return false;
		const re = resource.indexOf(":", ri);
		const rEnd = re === -1 ? resource.length : re;
		if (pEnd - pi !== rEnd - ri) return false;
		for (let k = 0; k < pEnd - pi; k++) {
			if (pattern.charCodeAt(pi + k) !== resource.charCodeAt(ri + k)) return false;
		}
		if (pe === -1) return re === -1;
		pi = pe + 1;
		ri = re === -1 ? resource.length + 1 : re + 1;
	}
}

/** A segment a wildcard may stand for. */
function isPlainSegment(segment: string): boolean {
	return segment !== "" && segment !== "." && segment !== "..";
}

/** Match the `/` separated parts of one colon segment. */
function matchPathParts(pattern: readonly string[], resource: readonly string[]): boolean {
	const m = pattern.length;
	const n = resource.length;
	// Without `**` every pattern part stands for exactly one resource part, so no table is needed.
	if (m === n && !pattern.includes("**")) {
		for (let i = 0; i < m; i++) {
			const p = pattern[i] as string;
			const r = resource[i] as string;
			if (p === "*") {
				if (r === "**" || !isPlainSegment(r)) return false;
			} else if (p !== r) {
				return false;
			}
		}
		return true;
	}
	if (!pattern.includes("**") && m !== n) return false;
	// ok[i][j]: pattern[i..] matches resource[j..]
	const ok: boolean[][] = Array.from({ length: m + 1 }, () =>
		new Array<boolean>(n + 1).fill(false),
	);
	(ok[m] as boolean[])[n] = true;
	for (let i = m - 1; i >= 0; i--) {
		const p = pattern[i] as string;
		const row = ok[i] as boolean[];
		const below = ok[i + 1] as boolean[];
		for (let j = n; j >= 0; j--) {
			if (j === n) {
				row[j] = false;
				continue;
			}
			const r = resource[j] as string;
			if (p === "**") {
				// One segment here, then either stop or keep consuming. A requested `*` or `**` token is
				// consumed as written (it is a pattern being compared, not a concrete name).
				row[j] = isPlainSegment(r) && (below[j + 1] === true || row[j + 1] === true);
			} else if (p === "*") {
				row[j] = r !== "**" && isPlainSegment(r) && below[j + 1] === true;
			} else {
				row[j] = p === r && below[j + 1] === true;
			}
		}
	}
	return (ok[0] as boolean[])[0] === true;
}

/** Path aware matcher. Opt in only. */
export function matchPathResource(pattern: string, resource: string): boolean {
	if (pattern === "*") return true;

	const patternParts = pattern.split(":");
	const resourceParts = resource.split(":");

	for (let i = 0; i < patternParts.length; i++) {
		const part = patternParts[i] as string;
		const last = i === patternParts.length - 1;
		if ((part === "*" || part === "**") && last) return true;
		const actual = resourceParts[i];
		if (actual === undefined) return false;
		if (part === "*" || part === "**") {
			// Before the last segment a whole segment wildcard is exactly one non-empty segment.
			if (actual === "" || actual === "**") return false;
			continue;
		}
		if (part === actual) continue;
		if (!part.includes("/") || !actual.includes("/")) return false;
		if (!matchPathParts(part.split("/"), actual.split("/"))) return false;
	}

	return patternParts.length === resourceParts.length;
}

/** Could two path segments (one colon segment each) select a common resource? Over-approximates: when unsure, true. */
function segmentsMayOverlap(x: string, y: string): boolean {
	if (x === y) return true;
	if (!x.includes("/") && !y.includes("/")) return false;
	const px = x.split("/");
	const py = y.split("/");
	const free = (p: string) => p === "*" || p === "**";
	let i = 0;
	while (i < px.length && i < py.length && px[i] !== "**" && py[i] !== "**") {
		const a = px[i] as string;
		const b = py[i] as string;
		if (!free(a) && !free(b) && a !== b) return false;
		i++;
	}
	const open = px.includes("**") || py.includes("**");
	if (!open) return px.length === py.length;
	let j = 1;
	while (j <= px.length - i && j <= py.length - i) {
		const a = px[px.length - j] as string;
		const b = py[py.length - j] as string;
		if (a === "**" || b === "**") break;
		if (!free(a) && !free(b) && a !== b) return false;
		j++;
	}
	return true;
}

/** Could the two patterns select a common resource under path matching? Over-approximates (never returns false for patterns that do overlap), so it is safe for deciding which parent rule constraints apply to a child. */
export function pathPatternsMayOverlap(a: string, b: string): boolean {
	if (a === "*" || b === "*") return true;
	const pa = a.split(":");
	const pb = b.split(":");
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
		const x = pa[i];
		const y = pb[i];
		if (x === "*" || x === "**" || y === "*" || y === "**") return true;
		if (x === undefined || y === undefined) return false;
		if (!segmentsMayOverlap(x, y)) return false;
	}
	return true;
}
