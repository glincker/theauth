import { runAdminApprovalFlow } from "./flow.js";

function out(line: string): void {
	process.stdout.write(`${line}\n`);
}

runAdminApprovalFlow({
	step: (n, text) => out(`\n[${n}] ${text}`),
	note: (text) => out(`    ${text}`),
})
	.then(() => process.exit(0))
	.catch((err: unknown) => {
		process.stderr.write(`Fatal error: ${err instanceof Error ? err.stack : String(err)}\n`);
		process.exit(1);
	});
