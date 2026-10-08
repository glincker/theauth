// Shared docs loader used by scripts/generate-llms.mjs and the CLI asset build.
// Reads docs/docs.json for page order and docs/*.mdx for content.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const SITE_URL = "https://docs.theauth.dev";

/** Collect page slugs from a docs.json navigation node, in nav order. */
function collectSlugs(node, out) {
	if (typeof node === "string") {
		out.push(node);
		return;
	}
	if (Array.isArray(node)) {
		for (const item of node) collectSlugs(item, out);
		return;
	}
	if (node && typeof node === "object") {
		for (const key of ["tabs", "groups", "pages"]) {
			if (node[key] !== undefined) collectSlugs(node[key], out);
		}
	}
}

function parseFrontmatter(source) {
	const match = /^---\n([\s\S]*?)\n---\n?/.exec(source);
	if (!match) return { meta: {}, body: source };
	const meta = {};
	for (const line of match[1].split("\n")) {
		const m = /^([A-Za-z_]+):\s*(.*)$/.exec(line);
		if (m) meta[m[1]] = m[2].replace(/^["']|["']$/g, "").trim();
	}
	return { meta, body: source.slice(match[0].length) };
}

/** Strip MDX-only syntax so the body reads as plain Markdown. */
export function stripMdx(body) {
	const lines = [];
	let inFence = false;
	for (const line of body.split("\n")) {
		if (/^\s*```/.test(line)) inFence = !inFence;
		if (!inFence && /^\s*(import|export)\s.+from\s/.test(line)) continue;
		lines.push(line);
	}
	return lines
		.join("\n")
		.replace(/<Frame[^>]*>[\s\S]*?<\/Frame>/g, "")
		.replace(/\n{3,}/g, "\n\n")
		.trim();
}

/**
 * Load every documented page. Excludes the Go docs (docs/go), which describe a
 * different SDK. Returns pages in navigation order, then any leftovers.
 */
export function loadDocs(docsDir) {
	const nav = JSON.parse(readFileSync(join(docsDir, "docs.json"), "utf8")).navigation;
	const slugs = [];
	collectSlugs(nav, slugs);
	const seen = new Set();
	const pages = [];
	for (const slug of slugs) {
		if (seen.has(slug) || slug.startsWith("go/") || slug === "go") continue;
		seen.add(slug);
		const file = join(docsDir, `${slug}.mdx`);
		if (!existsSync(file)) continue;
		const { meta, body } = parseFrontmatter(readFileSync(file, "utf8"));
		pages.push({
			slug,
			title: meta.title ?? slug,
			description: meta.description ?? "",
			url: `${SITE_URL}/${slug === "index" ? "" : slug}`,
			body: stripMdx(body),
		});
	}
	return pages;
}
