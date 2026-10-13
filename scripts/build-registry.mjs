// Writes the shadcn-compatible registry to registry/ (committed, so a raw URL works).
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildRegistry, registryIndex } from "./registry.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "registry");
const items = buildRegistry(join(root, "packages/ui/src"));

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const item of items) {
	writeFileSync(join(out, `${item.name}.json`), `${JSON.stringify(item, null, 2)}\n`);
}
writeFileSync(join(out, "registry.json"), `${JSON.stringify(registryIndex(items), null, 2)}\n`);
process.stdout.write(`Wrote ${items.length} registry items to registry/\n`);
