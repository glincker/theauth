/**
 * Path aware resource matching. Probe tests first: every authorization decision runs through matchResource,
 * so the default (colon) behavior is pinned against a frozen copy of the original matcher before the opt in
 * `path` mode is allowed to differ.
 */
import { describe, expect, it } from "vitest";
import { matchResource } from "../src/policy/abac.js";

/** Frozen copy of the matcher as it was before path mode existed. Never edit this. */
function legacyMatch(pattern: string, resource: string): boolean {
	if (pattern === "*") return true;
	const patternParts = pattern.split(":");
	const resourceParts = resource.split(":");
	for (let i = 0; i < patternParts.length; i++) {
		const part = patternParts[i];
		if (part === "*") return true;
		if (part !== resourceParts[i]) return false;
	}
	return patternParts.length === resourceParts.length;
}

/** Small deterministic PRNG so the generated corpus is the same on every run. */
function prng(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
		return s / 0x100000000;
	};
}

const PIECES = [
	"a",
	"b",
	"ros2",
	"mqtt",
	"srv",
	"*",
	"**",
	"",
	"/x",
	"/x/y",
	"/x/*",
	"/x/**",
	"/x/..",
	"/x//y",
	"/x/y/",
	"..",
	".",
	"a*",
	"/",
];

function corpus(seed: number, size: number): string[] {
	const next = prng(seed);
	const out = new Set<string>(["*", "", ":", "a", "a:b", "ros2:/x/y"]);
	while (out.size < size) {
		const segs = 1 + Math.floor(next() * 4);
		const parts: string[] = [];
		for (let i = 0; i < segs; i++) parts.push(PIECES[Math.floor(next() * PIECES.length)] as string);
		out.add(parts.join(":"));
	}
	return [...out];
}

const PATTERNS = corpus(1, 260);
const RESOURCES = corpus(2, 260);

describe("default matching is unchanged", () => {
	it("equals the frozen legacy matcher with no mode argument", () => {
		let checked = 0;
		for (const p of PATTERNS) {
			for (const r of RESOURCES) {
				expect(matchResource(p, r), `${p} vs ${r}`).toBe(legacyMatch(p, r));
				checked++;
			}
		}
		expect(checked).toBeGreaterThan(60_000);
	});

	it("equals the frozen legacy matcher in explicit colon mode and for undefined", () => {
		for (const p of PATTERNS) {
			for (const r of RESOURCES) {
				expect(matchResource(p, r, "colon"), `${p} vs ${r}`).toBe(legacyMatch(p, r));
				expect(matchResource(p, r, undefined), `${p} vs ${r}`).toBe(legacyMatch(p, r));
			}
		}
	});

	it("still treats a glob inside a colon segment as literal text", () => {
		expect(matchResource("ros2:/fleet/*", "ros2:/fleet/a")).toBe(false);
		expect(matchResource("ros2:/fleet/**", "ros2:/fleet/a/b")).toBe(false);
		expect(matchResource("ros2:/fleet/*", "ros2:/fleet/*")).toBe(true);
	});

	it("keeps the whole segment wildcard rule", () => {
		expect(matchResource("mcp:github:*", "mcp:github:repos")).toBe(true);
		expect(matchResource("mcp:github:*", "mcp:github")).toBe(true);
		expect(matchResource("mcp:github", "mcp:github:repos")).toBe(false);
	});
});

describe("path mode semantics", () => {
	const path = (p: string, r: string) => matchResource(p, r, "path");

	it("`*` matches exactly one path segment", () => {
		expect(path("ros2:/fleet/*", "ros2:/fleet/a")).toBe(true);
		expect(path("ros2:/fleet/*", "ros2:/fleet/a/b")).toBe(false);
		expect(path("ros2:/fleet/*", "ros2:/fleet")).toBe(false);
		expect(path("ros2:/fleet/*", "ros2:/other/a")).toBe(false);
		expect(path("ros2:/fleet/*/cmd", "ros2:/fleet/r1/cmd")).toBe(true);
		expect(path("ros2:/fleet/*/cmd", "ros2:/fleet/r1/x/cmd")).toBe(false);
	});

	it("`**` matches one or more path segments", () => {
		expect(path("ros2:/fleet/**", "ros2:/fleet/a")).toBe(true);
		expect(path("ros2:/fleet/**", "ros2:/fleet/a/b/c")).toBe(true);
		expect(path("ros2:/fleet/**", "ros2:/fleet")).toBe(false);
		expect(path("ros2:/fleet/**", "ros2:/fleetx/a")).toBe(false);
		expect(path("ros2:/fleet/**/cmd", "ros2:/fleet/a/b/cmd")).toBe(true);
		expect(path("ros2:/fleet/**/cmd", "ros2:/fleet/cmd")).toBe(false);
		expect(path("ros2:/fleet/**/cmd", "ros2:/fleet/a/cmd/x")).toBe(false);
	});

	it("works inside service and action namespaces", () => {
		expect(path("ros2:srv:/fleet/*", "ros2:srv:/fleet/reset")).toBe(true);
		expect(path("ros2:srv:/fleet/*", "ros2:/fleet/reset")).toBe(false);
		expect(path("ros2:action:/nav/**", "ros2:action:/nav/a/b")).toBe(true);
	});

	it("a path glob never crosses a colon boundary", () => {
		expect(path("ros2:/fleet/**", "ros2:/fleet/a:b")).toBe(false);
		expect(path("ros2:/fleet/*", "ros2:/fleet/a:srv")).toBe(false);
		expect(path("a/*", "a/b:c")).toBe(false);
	});

	it("wildcards never match empty, dot or dot dot segments", () => {
		expect(path("ros2:/fleet/*", "ros2:/fleet/")).toBe(false);
		expect(path("ros2:/fleet/*", "ros2:/fleet/..")).toBe(false);
		expect(path("ros2:/fleet/*", "ros2:/fleet/.")).toBe(false);
		expect(path("ros2:/fleet/**", "ros2:/fleet/a/../../admin")).toBe(false);
		expect(path("ros2:/fleet/**", "ros2:/fleet/a//b")).toBe(false);
		expect(path("ros2:/fleet/*/x", "ros2:/fleet/../x")).toBe(false);
		expect(path("ros2:/fleet/**", "ros2:/fleet/a/")).toBe(false);
	});

	it("an exact pattern still matches itself even with odd segments", () => {
		expect(path("ros2:/fleet/../x", "ros2:/fleet/../x")).toBe(true);
		expect(path("ros2:/fleet/a", "ros2:/fleet/a")).toBe(true);
		expect(path("ros2:/fleet/a", "ros2:/fleet/b")).toBe(false);
	});

	it("is case sensitive and does not decode", () => {
		expect(path("ros2:/Fleet/*", "ros2:/fleet/a")).toBe(false);
		expect(path("ros2:/fleet/*", "ros2:/fleet/%2e%2e")).toBe(true);
		expect(path("ros2:/fleet/a", "ros2:/fleet/%61")).toBe(false);
	});

	it("a partial glob inside a segment is literal", () => {
		expect(path("ros2:/fleet/r*", "ros2:/fleet/r1")).toBe(false);
		expect(path("ros2:/fleet/r*", "ros2:/fleet/r*")).toBe(true);
	});

	it("a wildcard in the requested resource is only covered by an equal or broader wildcard", () => {
		expect(path("ros2:/fleet/*", "ros2:/fleet/*")).toBe(true);
		expect(path("ros2:/fleet/**", "ros2:/fleet/*")).toBe(true);
		expect(path("ros2:/fleet/**", "ros2:/fleet/**")).toBe(true);
		expect(path("ros2:/fleet/*", "ros2:/fleet/**")).toBe(false);
		expect(path("ros2:/fleet/a", "ros2:/fleet/*")).toBe(false);
		expect(path("ros2:/fleet/**/b", "ros2:/fleet/**")).toBe(false);
		expect(path("ros2:/fleet/**", "ros2:/fleet/**/b")).toBe(true);
	});

	it("keeps the whole colon segment wildcard and the bare wildcard", () => {
		expect(path("*", "ros2:/a/b")).toBe(true);
		expect(path("ros2:*", "ros2:/a/b")).toBe(true);
		expect(path("ros2:srv:*", "ros2:srv:/a/b")).toBe(true);
		expect(path("ros2:srv:*", "ros2:/a/b")).toBe(false);
	});

	it("does not alias MQTT wildcards (design D8: `+` and `#` have no equivalent)", () => {
		expect(path("mqtt:sensors:+", "mqtt:sensors:temp")).toBe(false);
		expect(path("mqtt:sensors:#", "mqtt:sensors:temp")).toBe(false);
		expect(path("mqtt:sensors:*", "mqtt:sensors:temp:42")).toBe(true);
		expect(path("mqtt:sensors:temp", "mqtt:sensors:temp")).toBe(true);
	});
});

describe("a `*` in the middle of a pattern", () => {
	it("default mode: swallows the rest of the resource (pinned, widening surprise, see report)", () => {
		expect(matchResource("mqtt:a:*:b", "mqtt:a:x:c")).toBe(true);
		expect(matchResource("mqtt:a:*:b", "mqtt:a:x:y:z")).toBe(true);
		expect(matchResource("mqtt:a:*:b", "mqtt:a")).toBe(true);
		expect(matchResource("mqtt:a:*:b", "mqtt:z")).toBe(false);
	});

	it("path mode: a whole segment `*` before the last segment matches exactly one non-empty segment", () => {
		const path = (p: string, r: string) => matchResource(p, r, "path");
		expect(path("mqtt:a:*:b", "mqtt:a:x:b")).toBe(true);
		expect(path("mqtt:a:*:b", "mqtt:a:x:c")).toBe(false);
		expect(path("mqtt:a:*:b", "mqtt:a:x:y:z")).toBe(false);
		expect(path("mqtt:a:*:b", "mqtt:a::b")).toBe(false);
		expect(path("mqtt:a:*:b", "mqtt:a:**:b")).toBe(false);
		expect(path("mqtt:a:*", "mqtt:a:x:y:z")).toBe(true);
		expect(path("*:b", "x:b")).toBe(true);
		expect(path("*:b", "x:c")).toBe(false);
	});
});

describe("path mode never widens a grant that has no slash", () => {
	const noSlash = (s: string) => !s.includes("/");
	const noDoubleStar = (s: string) => !s.split(":").includes("**");
	// A whole segment `*` before the last segment is narrower in path mode (one segment, not the rest).
	const noMidStar = (s: string) => !s.split(":").slice(0, -1).includes("*");

	it("equals the legacy matcher for every pair without slashes or whole segment `**`", () => {
		let checked = 0;
		for (const p of PATTERNS.filter((x) => noSlash(x) && noDoubleStar(x) && noMidStar(x))) {
			for (const r of RESOURCES.filter(noSlash)) {
				expect(matchResource(p, r, "path"), `${p} vs ${r}`).toBe(legacyMatch(p, r));
				checked++;
			}
		}
		expect(checked).toBeGreaterThan(500);
	});

	it("never allows a resource the legacy matcher allows to be denied by a slash free exact pattern", () => {
		for (const p of PATTERNS.filter((x) => noSlash(x) && !x.includes("*"))) {
			for (const r of RESOURCES) {
				if (legacyMatch(p, r)) expect(matchResource(p, r, "path"), `${p} vs ${r}`).toBe(true);
			}
		}
	});
});

describe("path mode is never broader than the legacy matcher without slashes", () => {
	it("a slash free pattern in path mode only ever matches a subset of what legacy matched", () => {
		for (const p of PATTERNS.filter((x) => !x.includes("/") && !x.split(":").includes("**"))) {
			for (const r of RESOURCES.filter((x) => !x.includes("/"))) {
				if (matchResource(p, r, "path")) expect(legacyMatch(p, r), `${p} vs ${r}`).toBe(true);
			}
		}
	});
});

describe("path mode is never broader than a plain glob reading", () => {
	it("a pattern without wildcards matches only the identical resource", () => {
		const exact = PATTERNS.filter((p) => !p.includes("*"));
		for (const p of exact) {
			for (const r of RESOURCES) {
				expect(matchResource(p, r, "path"), `${p} vs ${r}`).toBe(p === r);
			}
		}
	});

	it("a wildcard never matches when the segment count differs and no `**` or whole colon wildcard is present", () => {
		const plain = (s: string) =>
			!s.split(":").some((seg) => seg === "*" || seg === "**") && !s.includes("**");
		for (const p of PATTERNS.filter((x) => x.includes("/*") && plain(x))) {
			for (const r of RESOURCES) {
				if (!matchResource(p, r, "path")) continue;
				const pp = p.split(":");
				const rr = r.split(":");
				expect(pp.length, `${p} vs ${r}`).toBe(rr.length);
				for (let i = 0; i < pp.length; i++) {
					expect((pp[i] as string).split("/").length, `${p} vs ${r}`).toBe(
						(rr[i] as string).split("/").length,
					);
				}
			}
		}
	});

	it("`..`, `.` and empty segments are only ever matched by a literal pattern segment", () => {
		for (const p of PATTERNS.filter((x) => x.includes("*") && x !== "*")) {
			for (const r of RESOURCES) {
				if (!matchResource(p, r, "path")) continue;
				const pSegs = p.split(":");
				for (let i = 0; i < pSegs.length; i++) {
					const seg = pSegs[i] as string;
					if (seg === "*" || seg === "**") break;
					const rSeg = (r.split(":")[i] ?? "") as string;
					const bad = rSeg
						.split("/")
						.some((x, idx) => idx > 0 && (x === "" || x === "." || x === ".."));
					if (bad) expect(seg, `${p} vs ${r}`).toBe(rSeg);
				}
			}
		}
	});
});
