#!/usr/bin/env node
// Copies the Go receipt fixture into the TypeScript test fixtures when the Go checkout is present.
// Never required in CI: the vendored copy is what the tests read.
import { copyFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, "../../go/audit/checkpoint/testdata/go-fixture.json");
const target = resolve(here, "../packages/core/tests/fixtures/receipts/go-fixture.json");

if (!existsSync(source)) {
	process.stdout.write(`skipped: ${source} not found\n`);
	process.exit(0);
}
copyFileSync(source, target);
process.stdout.write(`copied ${source} to ${target}\n`);
