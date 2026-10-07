import { ENV_PREFIX_NEW, ENV_PREFIX_OLD, mapImportPath, RENAME_MAP } from "./rename-map.js";

/**
 * Pure source transform for the Kavach to TheAuth rename. No file system access.
 * Identifiers are replaced only in code and comments, never inside string
 * literals, except import paths and `process.env` / `import.meta.env` names.
 */

export type SourceKind = "script" | "sfc" | "markup" | "dotenv";

export type FindingCategory = "header" | "table" | "unmapped";

export interface Finding {
	readonly line: number;
	readonly category: FindingCategory;
	readonly text: string;
}

export interface TransformResult {
	readonly output: string;
	/** Replacement counts keyed by old identifier, `env:KAVACH_X` or `import:old/path`. */
	readonly counts: ReadonlyMap<string, number>;
	readonly findings: readonly Finding[];
}

type SegmentKind = "code" | "string" | "comment";

interface Segment {
	kind: SegmentKind;
	text: string;
}

const NAME_LOOKUP: ReadonlyMap<string, string> = new Map(
	RENAME_MAP.map((e) => [e.old, e.canonical]),
);

const IDENT_ALTERNATION = [...NAME_LOOKUP.keys()].sort((a, b) => b.length - a.length).join("|");

// Group 1: env suffix for process.env.KAVACH_X / import.meta.env.KAVACH_X. Group 2: mapped identifier.
const CODE_PATTERN = new RegExp(
	`(?<![\\w$])(?:process\\.env|import\\.meta\\.env)\\s*\\.\\s*${ENV_PREFIX_OLD}(\\w+)|(?<![\\w$])(${IDENT_ALTERNATION})(?![\\w$])`,
	"g",
);

const BARE_ENV_PATTERN = new RegExp(`(?<![\\w$])${ENV_PREFIX_OLD}([A-Z0-9_]+)`, "g");

const IMPORT_CONTEXT =
	/(?:\bfrom|\bimport|\brequire\s*\(|\bimport\s*\(|\bmock\s*\(|\bimportActual\s*\()\s*$/;
const ENV_BRACKET_CONTEXT = /(?:process\.env|import\.meta\.env)\s*\[\s*$/;
const ENV_NAME = new RegExp(`^${ENV_PREFIX_OLD}\\w+$`);

function bump(counts: Map<string, number>, key: string): void {
	counts.set(key, (counts.get(key) ?? 0) + 1);
}

/** Find the end (exclusive) of a single-line string starting at `start`, or -1 if unterminated. */
function findStringEnd(src: string, start: number): number {
	const quote = src[start];
	for (let j = start + 1; j < src.length; j++) {
		const ch = src[j];
		if (ch === "\\") {
			j++;
			continue;
		}
		if (ch === "\n") return -1;
		if (ch === quote) return j + 1;
	}
	return -1;
}

/**
 * Read template text whose first character (the opening backtick or the `}` that
 * closed an expression) is at `from`; returns the exclusive end and whether a `${` opened.
 */
function readTemplateText(src: string, from: number): { end: number; opensExpr: boolean } {
	for (let j = from + 1; j < src.length; j++) {
		const ch = src[j];
		if (ch === "\\") {
			j++;
			continue;
		}
		if (ch === "`") return { end: j + 1, opensExpr: false };
		if (ch === "$" && src[j + 1] === "{") return { end: j + 2, opensExpr: true };
	}
	return { end: src.length, opensExpr: false };
}

/** Split script source into code, string and comment segments. Lossless: segments join to the input. */
export function tokenize(src: string): Segment[] {
	const segments: Segment[] = [];
	const exprDepths: number[] = [];
	let depth = 0;
	let code = "";
	let i = 0;

	const flush = (): void => {
		if (code !== "") {
			segments.push({ kind: "code", text: code });
			code = "";
		}
	};
	const pushTemplate = (from: number): number => {
		const { end, opensExpr } = readTemplateText(src, from);
		segments.push({ kind: "string", text: src.slice(from, end) });
		if (opensExpr) {
			exprDepths.push(depth);
			depth = 0;
		}
		return end;
	};

	while (i < src.length) {
		const ch = src[i] as string;
		const next = src[i + 1];
		if (ch === "/" && next === "/") {
			flush();
			const nl = src.indexOf("\n", i);
			const end = nl === -1 ? src.length : nl;
			segments.push({ kind: "comment", text: src.slice(i, end) });
			i = end;
		} else if (ch === "/" && next === "*") {
			flush();
			const close = src.indexOf("*/", i + 2);
			const end = close === -1 ? src.length : close + 2;
			segments.push({ kind: "comment", text: src.slice(i, end) });
			i = end;
		} else if (ch === '"' || ch === "'") {
			const end = findStringEnd(src, i);
			if (end === -1) {
				// An unterminated quote is prose (JSX text such as "don't"), not a string.
				code += ch;
				i++;
			} else {
				flush();
				segments.push({ kind: "string", text: src.slice(i, end) });
				i = end;
			}
		} else if (ch === "`") {
			flush();
			i = pushTemplate(i);
		} else if (ch === "{") {
			depth++;
			code += ch;
			i++;
		} else if (ch === "}") {
			if (depth === 0 && exprDepths.length > 0) {
				flush();
				depth = exprDepths.pop() as number;
				i = pushTemplate(i);
			} else {
				depth--;
				code += ch;
				i++;
			}
		} else {
			code += ch;
			i++;
		}
	}
	flush();
	return segments;
}

function replaceCode(text: string, counts: Map<string, number>): string {
	return text.replace(
		CODE_PATTERN,
		(match, envSuffix: string | undefined, ident: string | undefined) => {
			if (envSuffix !== undefined) {
				bump(counts, `env:${ENV_PREFIX_OLD}${envSuffix}`);
				return match.replace(ENV_PREFIX_OLD, ENV_PREFIX_NEW);
			}
			const canonical = ident === undefined ? undefined : NAME_LOOKUP.get(ident);
			if (ident === undefined || canonical === undefined) return match;
			bump(counts, ident);
			return canonical;
		},
	);
}

function replaceBareEnv(text: string, counts: Map<string, number>): string {
	return text.replace(BARE_ENV_PATTERN, (_match, suffix: string) => {
		bump(counts, `env:${ENV_PREFIX_OLD}${suffix}`);
		return `${ENV_PREFIX_NEW}${suffix}`;
	});
}

function transformString(text: string, previousCode: string, counts: Map<string, number>): string {
	const quote = text[0];
	if (text.length < 2 || (quote !== '"' && quote !== "'")) return text;
	const inner = text.slice(1, -1);
	if (IMPORT_CONTEXT.test(previousCode)) {
		const mapped = mapImportPath(inner);
		if (mapped === null) return text;
		bump(counts, `import:${inner}`);
		return `${quote}${mapped}${quote}`;
	}
	if (ENV_BRACKET_CONTEXT.test(previousCode) && ENV_NAME.test(inner)) {
		bump(counts, `env:${inner}`);
		return `${quote}${ENV_PREFIX_NEW}${inner.slice(ENV_PREFIX_OLD.length)}${quote}`;
	}
	return text;
}

function transformScript(src: string, counts: Map<string, number>): string {
	const segments = tokenize(src);
	let out = "";
	let previousCode = "";
	for (const seg of segments) {
		if (seg.kind === "code") {
			const replaced = replaceCode(seg.text, counts);
			out += replaced;
			previousCode = replaced;
		} else if (seg.kind === "comment") {
			out += replaceCode(seg.text, counts);
		} else {
			out += transformString(seg.text, previousCode, counts);
			previousCode = "";
		}
	}
	return out;
}

const SCRIPT_BLOCK = /(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi;

function transformSfc(src: string, counts: Map<string, number>): string {
	let out = "";
	let last = 0;
	for (const m of src.matchAll(SCRIPT_BLOCK)) {
		const start = m.index ?? 0;
		out += replaceCode(src.slice(last, start), counts);
		out += `${m[1] ?? ""}${transformScript(m[2] ?? "", counts)}${m[3] ?? ""}`;
		last = start + m[0].length;
	}
	return out + replaceCode(src.slice(last), counts);
}

const LEFTOVER_TOKEN = /[\w@$./-]*kavach[\w-]*/gi;

/** Report every remaining Kavach mention so a human can decide. Never edits. */
export function findLeftovers(src: string): Finding[] {
	const findings: Finding[] = [];
	const lines = src.split("\n");
	for (let n = 0; n < lines.length; n++) {
		const line = lines[n] as string;
		for (const m of line.matchAll(LEFTOVER_TOKEN)) {
			const text = m[0].replace(/[.\-/]+$/, "");
			let category: FindingCategory = "unmapped";
			if (/x-kavach-/i.test(text)) category = "header";
			else if (/kavach_\w+/.test(text)) category = "table";
			findings.push({ line: n + 1, category, text });
		}
	}
	return findings;
}

export function transformSource(source: string, kind: SourceKind): TransformResult {
	const counts = new Map<string, number>();
	let output: string;
	switch (kind) {
		case "script":
			output = transformScript(source, counts);
			break;
		case "sfc":
			output = transformSfc(source, counts);
			break;
		case "markup":
			output = replaceBareEnv(replaceCode(source, counts), counts);
			break;
		case "dotenv":
			output = replaceBareEnv(source, counts);
			break;
	}
	return { output, counts, findings: findLeftovers(output) };
}
