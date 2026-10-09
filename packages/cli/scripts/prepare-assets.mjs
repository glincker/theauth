// Copies the agent skill and a docs search index into dist/assets after tsup runs.
import { cpSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDocs } from "../../../scripts/docs-pages.mjs";

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(pkgDir, "../..");
const out = join(pkgDir, "dist/assets");

mkdirSync(out, { recursive: true });
cpSync(join(repoRoot, "skills/theauth/SKILL.md"), join(out, "SKILL.md"));
writeFileSync(join(out, "docs-index.json"), JSON.stringify(loadDocs(join(repoRoot, "docs"))));
process.stdout.write("Wrote dist/assets/SKILL.md and dist/assets/docs-index.json\n");
