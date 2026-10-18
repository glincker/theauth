/**
 * Write the generated OpenAPI document to sdks/openapi.json.
 *
 *   pnpm --filter @glinr/theauth exec jiti scripts/generate-openapi.ts
 *
 * Pass `check` to compare instead of write. It exits 1 when the checked-in file is stale.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { renderOpenAPIJson } from "../src/openapi-render.js";

const here = dirname(fileURLToPath(import.meta.url));
const target = resolve(here, "../../../sdks/openapi.json");
const next = renderOpenAPIJson();

if (process.argv.includes("check")) {
	const current = readFileSync(target, "utf8");
	if (current !== next) {
		process.stderr.write("sdks/openapi.json is stale. Run the generator and commit the result.\n");
		process.exit(1);
	}
} else {
	writeFileSync(target, next);
	process.stdout.write(`wrote ${target}\n`);
}
