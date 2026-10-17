#!/usr/bin/env node
// Builds GitHub release notes for a core version from the changesets CHANGELOG files.
// Usage: node scripts/release-notes.mjs <tag> [--prev <prevTag>] [--sha <commit>]. Markdown goes to stdout.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const tag = args[0];
if (!tag || !/^v\d+\.\d+\.\d+/.test(tag)) {
	// biome-ignore lint/suspicious/noConsole: CLI script reports usage on stderr
	console.error("usage: release-notes.mjs <tag> [--prev <tag>] [--sha <commit>]");
	process.exit(1);
}
const flag = (name) => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : undefined;
};
const git = (...a) =>
	execFileSync("git", a, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
const version = tag.slice(1);
const sha = flag("--sha") || git("rev-parse", "HEAD");
const semver = (v) => v.replace(/^v/, "").split(/[.-]/).slice(0, 3).map(Number);
const cmp = (a, b) => {
	const x = semver(a),
		y = semver(b);
	for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
	return 0;
};
const prev =
	flag("--prev") ||
	git("tag", "--list", "v*")
		.split("\n")
		.filter((t) => /^v\d+\.\d+\.\d+$/.test(t) && cmp(t, tag) < 0)
		.sort(cmp)
		.pop();
const prevSha = prev ? git("rev-list", "-n1", prev) : null;

const walk = (dir, out = []) => {
	for (const name of readdirSync(dir)) {
		if (name === "node_modules" || name === "dist") continue;
		const p = join(dir, name);
		if (statSync(p).isDirectory()) walk(p, out);
		else if (name === "package.json") out.push(p);
	}
	return out;
};
const pkgAt = (rev, path) => {
	try {
		return JSON.parse(rev ? git("show", `${rev}:${path}`) : readFileSync(path, "utf8"));
	} catch {
		return null;
	}
};

const changed = [];
for (const path of walk("packages")) {
	const now = pkgAt(sha, path);
	if (!now || now.private || !now.name || !now.version) continue;
	const before = prevSha ? pkgAt(prevSha, path) : null;
	if (before && before.version === now.version) continue;
	changed.push({
		path,
		name: now.name,
		version: now.version,
		from: before ? before.version : null,
		dir: path.replace(/\/package\.json$/, ""),
	});
}
changed.sort((a, b) =>
	a.name === "@glinr/theauth" ? -1 : b.name === "@glinr/theauth" ? 1 : a.name.localeCompare(b.name),
);

function section(dir, ver) {
	const file = join(dir, "CHANGELOG.md");
	let text;
	try {
		text = sha ? git("show", `${sha}:${file}`) : readFileSync(file, "utf8");
	} catch {
		return null;
	}
	const start = text.indexOf(`\n## ${ver}\n`);
	if (start < 0) return null;
	const rest = text.slice(start + 1);
	const end = rest.indexOf("\n## ", 4);
	const body = rest.slice(rest.indexOf("\n") + 1, end < 0 ? undefined : end);
	const groups = {};
	let current = null;
	for (const line of body.split("\n")) {
		const h = /^### (.+)$/.exec(line);
		if (h) {
			current = groups[h[1]] = [];
			continue;
		}
		if (!current) continue;
		if (/^- /.test(line)) current.push(line.slice(2));
		else if (current.length && (line.startsWith("  ") || line.trim() === ""))
			current[current.length - 1] += `\n${line.replace(/^ {2}/, "")}`;
	}
	for (const k of Object.keys(groups))
		groups[k] = groups[k].map((e) => e.replace(/^[0-9a-f]{7,}: /, "").trim()).filter(Boolean);
	return groups;
}

const core = changed.find((p) => p.name === "@glinr/theauth");
const coreSection = core ? section(core.dir, version) : null;
const heading = {
	"Major Changes": "Breaking changes",
	"Minor Changes": "Features and changes",
	"Patch Changes": "Fixes",
};
const RAW = "https://raw.githubusercontent.com/glincker/theauth/main";
const out = [];
// Theme aware header, same layout as the thesvg and levelrail releases.
out.push(
	`<p align="center">
  <a href="https://theauth.dev">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="${RAW}/docs/logo/wordmark-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="${RAW}/docs/logo/wordmark-light.svg" />
      <img src="${RAW}/docs/logo/wordmark-light.svg" alt="theAuth" height="48" />
    </picture>
  </a>
</p>

<p align="center">
  <a href="https://docs.theauth.dev/quickstart">Quickstart</a> &middot;
  <a href="https://docs.theauth.dev">Docs</a> &middot;
  <a href="https://www.npmjs.com/package/@glinr/theauth">npm</a> &middot;
  <a href="https://github.com/glincker/theauth-go">Go</a> &middot;
  <a href="https://github.com/glincker/theauth/discussions">Discussions</a>
</p>

---
`,
);
out.push(`## theAuth ${version}`);
out.push(
	"\nOpen-source authentication and authorization for AI agents, MCP servers and apps. Agent identity, delegation, an OAuth 2.1 authorization server for MCP, DPoP, passkeys, SSO and SCIM in TypeScript. Self-hosted and MIT licensed.",
);
if (!coreSection)
	out.push("\nRelease notes for this version were not found in the core changelog.");

const isDepsOnly = (e) => /^Updated dependencies/.test(e);
let breaking = false;
for (const [key, label] of Object.entries(heading)) {
	const entries = (coreSection?.[key] || []).filter((e) => !isDepsOnly(e));
	if (!entries.length) continue;
	if (key === "Major Changes") breaking = true;
	out.push(`\n### ${label}\n`);
	for (const e of entries) {
		const [first, ...more] = e.split(/\n\s*\n/);
		out.push(
			`- ${first.replace(/\n/g, "\n  ")}${more.length ? " (details in the package changelog)" : ""}`,
		);
	}
}
const majors = changed.filter(
	(p) => p.from && Number(p.from.split(".")[0]) < Number(p.version.split(".")[0]),
);
if (majors.length) breaking = true;

if (breaking) {
	out.push("\n### Upgrading\n");
	if (coreSection && !(coreSection["Major Changes"] || []).length) {
		out.push(
			`${majors.length} packages move to the ${version.split(".")[0]}.x line in this release (${majors
				.map((p) => `\`${p.name}\``)
				.slice(0, 4)
				.join(
					", ",
				)}${majors.length > 4 ? ", and more" : ""}). This is a versioning change with no API change, and framework adapters keep working because their peer ranges accept it. Details: https://github.com/glincker/theauth/blob/main/STABILITY.md`,
		);
	} else {
		out.push(
			`${
				majors.length
					? `${majors.length} packages move to a new major version in this release (${majors
							.map((p) => `\`${p.name}\` ${p.version}`)
							.slice(0, 4)
							.join(", ")}${majors.length > 4 ? ", and more" : ""}). `
					: ""
			}Upgrade \`@glinr/theauth\` and every adapter together. Migration guide: https://docs.theauth.dev/migrate`,
		);
	}
}

out.push("\n### Packages in this release\n");
out.push("| Package | Version | Changelog |", "|---|---|---|");
for (const p of changed) {
	out.push(
		`| [\`${p.name}\`](https://www.npmjs.com/package/${p.name}/v/${p.version}) | ${p.from ? `${p.from} to ${p.version}` : `${p.version} (new)`} | [CHANGELOG](https://github.com/glincker/theauth/blob/${tag}/${p.dir}/CHANGELOG.md) |`,
	);
}

out.push("\n### Install\n");
out.push(
	"```bash",
	`npm install @glinr/theauth@${version}`,
	`pnpm add @glinr/theauth@${version}`,
	`yarn add @glinr/theauth@${version}`,
	`bun add @glinr/theauth@${version}`,
	"```",
);
out.push("\n### Resources\n");
out.push(
	"- [Quickstart](https://docs.theauth.dev/quickstart) and [agent identity](https://docs.theauth.dev/agents)",
	"- [MCP OAuth 2.1](https://docs.theauth.dev/mcp) and [DPoP](https://docs.theauth.dev/dpop)",
	"- [Stability and versioning](https://github.com/glincker/theauth/blob/main/STABILITY.md)",
	"- [Migration guides](https://docs.theauth.dev/migrate)",
	"- [Go library](https://github.com/glincker/theauth-go) ([releases](https://github.com/glincker/theauth-go/releases))",
	"- Questions and ideas: [GitHub Discussions](https://github.com/glincker/theauth/discussions)",
	"- Security reports: [SECURITY.md](https://github.com/glincker/theauth/blob/main/SECURITY.md)",
);
if (prev)
	out.push(`\n**Full changelog**: https://github.com/glincker/theauth/compare/${prev}...${tag}`);
// biome-ignore lint/suspicious/noConsole: CLI script writes the notes to stdout
console.log(out.join("\n").replace(/[\u2013\u2014]/g, "-"));
