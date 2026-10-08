// Writes template-versions.json: the current version of every @glinr/*
// workspace package. The scaffolder uses it to pin template dependencies to
// the release it ships with, so templates cannot fall behind npm.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packagesDir = join(here, "..", "..");
const versions = {};

for (const group of [packagesDir, join(packagesDir, "adapters")]) {
	for (const entry of readdirSync(group, { withFileTypes: true })) {
		if (!entry.isDirectory()) continue;
		try {
			const pkg = JSON.parse(readFileSync(join(group, entry.name, "package.json"), "utf-8"));
			if (pkg.name?.startsWith("@glinr/") && pkg.version) versions[pkg.name] = pkg.version;
		} catch {
			// not a package directory
		}
	}
}

const sorted = Object.fromEntries(Object.entries(versions).sort(([a], [b]) => a.localeCompare(b)));
writeFileSync(join(here, "..", "template-versions.json"), `${JSON.stringify(sorted, null, 2)}\n`);
