#!/usr/bin/env node
// Thin forwarder so `npx theauth` runs the @glinr/theauth-cli binary.
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const cliEntry = fileURLToPath(import.meta.resolve("@glinr/theauth-cli"));
const cliBin = join(dirname(cliEntry), "bin.js");

const child = spawn(process.execPath, [cliBin, ...process.argv.slice(2)], { stdio: "inherit" });
child.on("exit", (code, signal) => {
	if (signal) process.kill(process.pid, signal);
	else process.exit(code ?? 1);
});
child.on("error", (err) => {
	process.stderr.write(`theauth: failed to start @glinr/theauth-cli: ${err.message}\n`);
	process.exit(1);
});
