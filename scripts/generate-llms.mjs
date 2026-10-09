// Generates docs/llms.txt (index) and docs/llms-full.txt (full text) from docs/*.mdx.
// Usage: node scripts/generate-llms.mjs [--check]
// With --check, exits 1 if the committed files are out of date.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDocs, SITE_URL } from "./docs-pages.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const docsDir = join(root, "docs");

export function buildLlms(pages) {
	const index = [
		"# theAuth",
		"",
		"> Open-source auth for AI agents and humans. Agent identity, delegation, MCP OAuth 2.1, passkeys and SSO for TypeScript.",
		"",
		"Install the SDK with `pnpm add @glinr/theauth`. The full text of every page is in llms-full.txt.",
		"",
		"## Docs",
		"",
		...pages.map((p) => `- [${p.title}](${p.url})${p.description ? `: ${p.description}` : ""}`),
		"",
	].join("\n");
	const full = [
		"# theAuth documentation",
		"",
		...pages.flatMap((p) => [`# ${p.title}`, "", `Source: ${p.url}`, "", p.body, "", "---", ""]),
	].join("\n");
	return { index, full };
}

const pages = loadDocs(docsDir);
const { index, full } = buildLlms(pages);
const targets = [
	[join(docsDir, "llms.txt"), index],
	[join(docsDir, "llms-full.txt"), full],
];

if (process.argv.includes("--check")) {
	const stale = targets.filter(([p, c]) => !existsSync(p) || readFileSync(p, "utf8") !== c);
	if (stale.length > 0) {
		process.stderr.write("llms files are out of date. Run: node scripts/generate-llms.mjs\n");
		process.exit(1);
	}
} else {
	for (const [p, c] of targets) writeFileSync(p, c);
	process.stdout.write(
		`Wrote ${pages.length} pages to docs/llms.txt and docs/llms-full.txt (${SITE_URL})\n`,
	);
}
