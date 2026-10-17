import type { Options } from "./types.js";

export interface CliArgs {
	options: Options;
	json: boolean;
	verbose: boolean;
	strict: boolean;
	badgePath: string | null;
	help: boolean;
	version: boolean;
}

export const USAGE = `Usage: theauth-conformance <url> [options]

Black-box agent-auth checks for any OAuth 2.1 or MCP authorization server or resource server.

Options:
  --json                 Print the report as JSON
  --badge <file>         Write a shields.io endpoint badge JSON file
  --resource <url>       Protected MCP endpoint to probe for the 401 challenge
  --client-id <id>       Use this client instead of registering one through DCR
  --redirect-uri <uri>   Redirect URI registered for --client-id
  --token <token>        Access token, only used to read its audience
                         (or THEAUTH_CONFORMANCE_TOKEN)
  --refresh-token <tok>  Refresh token for the rotation check; it gets consumed
                         (or THEAUTH_CONFORMANCE_REFRESH_TOKEN)
  --timeout <ms>         Per-request timeout, default 10000
  --verbose              Include evidence in the human report
  --strict               Exit 1 on any failed check, not only MUST failures
  -h, --help             Show this help
  -v, --version          Show the version

Exit codes: 0 ok, 1 failed checks, 2 usage error.
`;

export class UsageError extends Error {}

const VALUE_FLAGS = new Set([
	"--badge",
	"--resource",
	"--client-id",
	"--redirect-uri",
	"--token",
	"--refresh-token",
	"--timeout",
]);

export function parseArgs(argv: string[], env: Record<string, string | undefined>): CliArgs {
	const values = new Map<string, string>();
	const flags = new Set<string>();
	let target: string | null = null;
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i] ?? "";
		if (VALUE_FLAGS.has(arg)) {
			const value = argv[i + 1];
			if (value === undefined || value.startsWith("--")) {
				throw new UsageError(`${arg} needs a value`);
			}
			values.set(arg, value);
			i += 1;
		} else if (arg.startsWith("-")) {
			flags.add(arg);
		} else if (target === null) {
			target = arg;
		} else {
			throw new UsageError(`Unexpected argument: ${arg}`);
		}
	}
	const help = flags.has("--help") || flags.has("-h");
	const version = flags.has("--version") || flags.has("-v");
	const known = ["--json", "--verbose", "--strict", "--help", "-h", "--version", "-v"];
	for (const flag of flags) {
		if (!known.includes(flag)) throw new UsageError(`Unknown option: ${flag}`);
	}
	if (!help && !version) {
		if (target === null) throw new UsageError("Missing <url>");
		try {
			new URL(target);
		} catch {
			throw new UsageError(`Not a valid URL: ${target}`);
		}
	}
	const timeout = Number(values.get("--timeout") ?? "10000");
	if (!Number.isFinite(timeout) || timeout <= 0) throw new UsageError("--timeout must be positive");
	const accessToken = values.get("--token") ?? env.THEAUTH_CONFORMANCE_TOKEN;
	const refreshToken = values.get("--refresh-token") ?? env.THEAUTH_CONFORMANCE_REFRESH_TOKEN;
	const resource = values.get("--resource");
	const clientId = values.get("--client-id");
	const redirectUri = values.get("--redirect-uri");
	return {
		options: {
			target: target ?? "",
			timeoutMs: timeout,
			...(resource ? { resource } : {}),
			...(clientId ? { clientId } : {}),
			...(redirectUri ? { redirectUri } : {}),
			...(accessToken ? { accessToken } : {}),
			...(refreshToken ? { refreshToken } : {}),
		},
		json: flags.has("--json"),
		verbose: flags.has("--verbose"),
		strict: flags.has("--strict"),
		badgePath: values.get("--badge") ?? null,
		help,
		version,
	};
}
