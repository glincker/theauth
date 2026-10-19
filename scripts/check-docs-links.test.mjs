// Run with: node --test scripts/check-docs-links.test.mjs
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { findAllProblems } from "./check-docs-links.mjs";

const REAL_DOCS = join(dirname(fileURLToPath(import.meta.url)), "..", "docs");
const tmp = mkdtempSync(join(tmpdir(), "docs-links-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function fixture(name, files) {
	const dir = join(tmp, name);
	for (const [path, body] of Object.entries(files)) {
		const full = join(dir, path);
		mkdirSync(dirname(full), { recursive: true });
		writeFileSync(full, body);
	}
	return dir;
}

test("flags missing nav pages, broken links and broken anchors, and skips code examples", () => {
	const dir = fixture("broken", {
		"docs.json": JSON.stringify({
			navigation: { groups: [{ group: "Start", pages: ["index", "guide/setup", "gone"] }] },
		}),
		"index.mdx": [
			"# Home",
			"",
			"[Setup](/guide/setup#install-steps) and [Missing](/nope)",
			"",
			"[Bad anchor](/guide/setup#no-such-heading) [Same page](#home)",
			"",
			"`[inline](/inline-only)` is code.",
			"",
			"```tsx",
			'<a href="/sign-in">Sign in</a>',
			"```",
			"",
			'<img src="/images/logo.png" />',
		].join("\n"),
		"guide/setup.mdx": "## Install steps\n\nSee [Home](/)\n",
	});

	const problems = findAllProblems(dir).map((p) => `${p.file} ${p.link}`);
	assert.deepEqual(problems.sort(), [
		"docs.json gone",
		"index.mdx /guide/setup#no-such-heading",
		"index.mdx /images/logo.png",
		"index.mdx /nope",
	]);
});

test("accepts index pages, static files and loosely matched anchors", () => {
	const dir = fixture("clean", {
		"docs.json": JSON.stringify({ navigation: ["index", "adapters/nextjs"] }),
		"index.mdx":
			"# Home\n\n[Adapter](/adapters/nextjs#app-router-setup) ![logo](/images/logo.png)\n",
		"adapters/nextjs.mdx": "## App Router and Pages\n\n### App Router setup\n\n[Home](/#home)\n",
		"images/logo.png": "not really a png",
	});
	assert.deepEqual(findAllProblems(dir), []);
});

test("the shipped docs have no broken navigation or links", () => {
	assert.deepEqual(findAllProblems(REAL_DOCS), []);
});
