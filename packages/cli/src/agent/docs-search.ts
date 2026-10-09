import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface DocPage {
	slug: string;
	title: string;
	description: string;
	url: string;
	body: string;
}

export interface SearchHit {
	slug: string;
	title: string;
	url: string;
	score: number;
	snippet: string;
}

const here = dirname(fileURLToPath(import.meta.url));

/** Where bundled assets live: dist/assets when built, otherwise the monorepo checkout. */
export function assetCandidates(name: string): string[] {
	return [
		join(here, "assets", name),
		join(here, "../dist/assets", name),
		join(here, "../../dist/assets", name),
	];
}

let cached: DocPage[] | null = null;

export function loadDocPages(): DocPage[] {
	if (cached) return cached;
	for (const file of assetCandidates("docs-index.json")) {
		if (existsSync(file)) {
			cached = JSON.parse(readFileSync(file, "utf8")) as DocPage[];
			return cached;
		}
	}
	return [];
}

/** Test hook: replace or clear the page cache. */
export function setDocPages(pages: DocPage[] | null): void {
	cached = pages;
}

function tokenize(text: string): string[] {
	return text
		.toLowerCase()
		.split(/[^a-z0-9_]+/)
		.filter((t) => t.length > 1);
}

function countOccurrences(haystack: string, needle: string): number {
	let count = 0;
	let from = 0;
	while (count < 50) {
		const i = haystack.indexOf(needle, from);
		if (i === -1) break;
		count++;
		from = i + needle.length;
	}
	return count;
}

function makeSnippet(body: string, terms: string[]): string {
	const lower = body.toLowerCase();
	let at = -1;
	for (const t of terms) {
		const i = lower.indexOf(t);
		if (i !== -1 && (at === -1 || i < at)) at = i;
	}
	const start = Math.max(0, at === -1 ? 0 : at - 80);
	return body
		.slice(start, start + 320)
		.replace(/\s+/g, " ")
		.trim();
}

export function searchDocs(pages: DocPage[], query: string, limit = 5): SearchHit[] {
	const terms = tokenize(query);
	if (terms.length === 0) return [];
	const hits: SearchHit[] = [];
	for (const page of pages) {
		const title = page.title.toLowerCase();
		const desc = page.description.toLowerCase();
		const slug = page.slug.toLowerCase();
		const body = page.body.toLowerCase();
		let score = 0;
		for (const t of terms) {
			if (title.includes(t)) score += 10;
			if (slug.includes(t)) score += 6;
			if (desc.includes(t)) score += 4;
			score += Math.min(countOccurrences(body, t), 10);
		}
		if (score > 0) {
			hits.push({
				slug: page.slug,
				title: page.title,
				url: page.url,
				score,
				snippet: makeSnippet(page.body, terms),
			});
		}
	}
	return hits.sort((a, b) => b.score - a.score).slice(0, Math.max(1, Math.min(limit, 20)));
}
