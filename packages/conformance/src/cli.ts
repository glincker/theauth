import { writeFile } from "node:fs/promises";
import { parseArgs, USAGE, UsageError } from "./args.js";
import { buildBadge } from "./badge.js";
import { formatReport } from "./report.js";
import { runSuite } from "./runner.js";
import { VERSION } from "./version.js";

/** The only place the package writes to stdout or stderr. */
function out(text: string): void {
	process.stdout.write(text);
}

function err(text: string): void {
	process.stderr.write(text);
}

export async function main(
	argv: string[],
	env: Record<string, string | undefined>,
): Promise<number> {
	let args: ReturnType<typeof parseArgs>;
	try {
		args = parseArgs(argv, env);
	} catch (error) {
		if (error instanceof UsageError) {
			err(`${error.message}\n\n${USAGE}`);
			return 2;
		}
		throw error;
	}
	if (args.help) {
		out(USAGE);
		return 0;
	}
	if (args.version) {
		out(`${VERSION}\n`);
		return 0;
	}

	const report = await runSuite(args.options);
	if (args.badgePath) {
		await writeFile(args.badgePath, `${JSON.stringify(buildBadge(report), null, 2)}\n`, "utf8");
	}
	out(args.json ? `${JSON.stringify(report, null, 2)}\n` : formatReport(report, args.verbose));

	const failing = args.strict ? report.summary.fail : report.summary.mustFailed;
	return failing > 0 ? 1 : 0;
}
