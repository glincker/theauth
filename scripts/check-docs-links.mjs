// Checks the docs site for broken references: every docs.json page must have a file, and every
// root-relative link or image in docs/*.mdx must resolve to a page or static file. Anchors on
// internal links must match a heading on the target page.
// Usage: node scripts/check-docs-links.mjs [docsDir]
// Links inside fenced code blocks and inline code are examples, not references, so they are skipped.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { collectSlugs } from "./docs-pages.mjs";

const DEFAULT_DOCS = join(dirname(fileURLToPath(import.meta.url)), "..", "docs");

/** Drop fenced code blocks, keeping line count stable so no line numbers shift. */
function stripFences(source) {
	let inFence = false;
	return source
		.split("\n")
		.map((line) => {
			if (/^\s*```/.test(line)) {
				inFence = !inFence;
				return "";
			}
			return inFence ? "" : line;
		})
		.join("\n");
}

/**
 * Compare anchors loosely: Mintlify, GitHub and hand-written links disagree on how to slug
 * punctuation such as dots, slashes and doubled hyphens, so both sides drop everything but letters and digits.
 */
export function normalizeAnchor(text) {
	return text.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function headingsOf(file, cache) {
	if (!cache.has(file)) {
		const set = new Set();
		for (const line of stripFences(readFileSync(file, "utf8")).split("\n")) {
			const m = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
			if (m) set.add(normalizeAnchor(m[1]));
		}
		cache.set(file, set);
	}
	return cache.get(file);
}

/** Map a root-relative path (`/a/b`) to a file under docsDir, or null. */
export function resolveRootPath(docsDir, path) {
	const rel = path.replace(/^\/+/, "").replace(/\/+$/, "");
	const candidates = [`${rel}.mdx`, `${rel}.md`, join(rel, "index.mdx"), rel];
	for (const candidate of candidates) {
		const full = join(docsDir, candidate);
		if (existsSync(full) && statSync(full).isFile()) return full;
	}
	return null;
}

function listDocFiles(dir, out = []) {
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) listDocFiles(full, out);
		else if (/\.(mdx|md)$/.test(entry)) out.push(full);
	}
	return out;
}

/** Problems with the navigation: each docs.json page must have a source file. */
export function findMissingNavPages(docsDir) {
	const nav = JSON.parse(readFileSync(join(docsDir, "docs.json"), "utf8")).navigation;
	const slugs = [];
	collectSlugs(nav, slugs);
	return [...new Set(slugs)]
		.filter(
			(slug) =>
				!existsSync(join(docsDir, `${slug}.mdx`)) && !existsSync(join(docsDir, `${slug}.md`)),
		)
		.map((slug) => ({
			file: "docs.json",
			link: slug,
			reason: "navigation page has no .mdx or .md file",
		}));
}

/** Problems inside the page sources: broken root-relative links, images and anchors. */
export function findBrokenLinks(docsDir) {
	const problems = [];
	const headingCache = new Map();
	const linkPattern = /\]\((\/[^)\s]*|#[^)\s]*)\)|(?:href|src)=["'](\/[^"'\s]*|#[^"'\s]*)["']/g;
	for (const file of listDocFiles(docsDir)) {
		const where = relative(docsDir, file);
		const prose = stripFences(readFileSync(file, "utf8"))
			.split("\n")
			.map((line) => line.replace(/`[^`\n]*`/g, ""))
			.join("\n");
		for (const match of prose.matchAll(linkPattern)) {
			const raw = match[1] ?? match[2];
			const [pathPart, hash] = raw.split("#");
			const path = pathPart.split("?")[0];
			let target = file;
			if (path !== "") {
				const resolved = resolveRootPath(docsDir, path);
				if (!resolved) {
					problems.push({ file: where, link: raw, reason: "no page or static file at this path" });
					continue;
				}
				target = resolved;
			}
			if (hash && /\.(mdx|md)$/.test(target)) {
				if (!headingsOf(target, headingCache).has(normalizeAnchor(hash))) {
					problems.push({ file: where, link: raw, reason: "no heading matches this anchor" });
				}
			}
		}
	}
	return problems;
}

export function findAllProblems(docsDir) {
	return [...findMissingNavPages(docsDir), ...findBrokenLinks(docsDir)];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const docsDir = process.argv[2] ? join(process.cwd(), process.argv[2]) : DEFAULT_DOCS;
	const problems = findAllProblems(docsDir);
	if (problems.length > 0) {
		for (const p of problems) process.stderr.write(`${p.file}: ${p.link} (${p.reason})\n`);
		process.stderr.write(`${problems.length} broken docs reference(s)\n`);
		process.exit(1);
	}
	process.stdout.write("docs links OK\n");
}
