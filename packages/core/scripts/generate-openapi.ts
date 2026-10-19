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
import { applyRegion, regions } from "./sdk-decision-codes.js";

const here = dirname(fileURLToPath(import.meta.url));
const target = resolve(here, "../../../sdks/openapi.json");
const next = renderOpenAPIJson();

const root = resolve(here, "../../..");

/** Rewrite the generated decision code regions of the Python and Go clients, or list the stale files. */
function syncClientCodes(write: boolean): string[] {
	const stale: string[] = [];
	const files = new Map<string, string>();
	for (const region of regions()) {
		const path = resolve(root, region.file);
		const before = files.get(path) ?? readFileSync(path, "utf8");
		const after = applyRegion(before, region);
		if (after === null) throw new Error(`${region.file}: missing generated region markers`);
		files.set(path, after);
		if (after !== readFileSync(path, "utf8") && !stale.includes(region.file))
			stale.push(region.file);
	}
	if (write) for (const [path, text] of files) writeFileSync(path, text);
	return stale;
}

if (process.argv.includes("check")) {
	const current = readFileSync(target, "utf8");
	const stale = syncClientCodes(false);
	if (current !== next || stale.length > 0) {
		process.stderr.write(
			`${[current !== next ? "sdks/openapi.json" : "", ...stale].filter(Boolean).join(", ")} stale. Run the generator and commit the result.\n`,
		);
		process.exit(1);
	}
} else {
	writeFileSync(target, next);
	syncClientCodes(true);
	process.stdout.write(`wrote ${target} and the client decision code lists\n`);
}
