// Copies the agent skill and a docs search index into dist/assets after tsup runs.
import { cpSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDocs } from "../../../scripts/docs-pages.mjs";
import { buildRegistry } from "../../../scripts/registry.mjs";

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(pkgDir, "../..");
const out = join(pkgDir, "dist/assets");

mkdirSync(out, { recursive: true });
cpSync(join(repoRoot, "skills/theauth/SKILL.md"), join(out, "SKILL.md"));
writeFileSync(join(out, "docs-index.json"), JSON.stringify(loadDocs(join(repoRoot, "docs"))));
const registryOut = join(out, "registry");
mkdirSync(registryOut, { recursive: true });
for (const item of buildRegistry(join(repoRoot, "packages/ui/src"))) {
	writeFileSync(join(registryOut, `${item.name}.json`), JSON.stringify(item));
}
process.stdout.write(
	"Wrote dist/assets/SKILL.md, dist/assets/docs-index.json and dist/assets/registry\n",
);
