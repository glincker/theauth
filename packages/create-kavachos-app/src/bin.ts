#!/usr/bin/env node
import { main } from "./index.js";

main().catch((err: unknown) => {
	process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
	process.exit(1);
});
