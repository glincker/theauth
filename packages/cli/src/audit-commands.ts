/**
 * `theauth audit verify` and `theauth audit replay`.
 *
 * Kept in its own file so bin.ts only needs one import and one switch case.
 * The commands open the database read-only in spirit: they never run
 * migrations and never write.
 */

import type { createAuditModule } from "@glinr/theauth";

type AuditModule = ReturnType<typeof createAuditModule>;

export const AUDIT_HELP = `
theauth audit

Usage:
  theauth audit verify [--agent <id>] [--from <iso>] [--to <iso>] [--json]
  theauth audit replay --agent <id> [--since <iso>] [--until <iso>] [--user <id>] [--json]

Options:
  --db <url>     Database URL (default: DATABASE_URL). postgres://, mysql://,
                 or a SQLite file path.
  --json         Machine readable output.

Environment:
  DATABASE_URL               Database to read.
  THEAUTH_AUDIT_HMAC_KEY     The audit.hmacKey the app runs with, if it sets one.

verify walks each agent's hash chain and prints the first broken link with the
row ids involved. It exits 1 when the chain is broken. replay prints one
agent's timeline (actions, decisions, delegations, approvals, token events)
and the chain verification status for that window.
`;

export interface AuditArgs {
	help: boolean;
	subcommand: "verify" | "replay" | null;
	agent: string | null;
	user: string | null;
	from: Date | null;
	to: Date | null;
	json: boolean;
	db: string | null;
	error: string | null;
}

function parseDate(flag: string, value: string | undefined): { date: Date | null; error?: string } {
	if (value === undefined) return { date: null, error: `${flag} needs a value` };
	const date = new Date(value);
	if (Number.isNaN(date.getTime()))
		return { date: null, error: `${flag} is not a valid date: ${value}` };
	return { date };
}

export function parseAuditArgs(args: string[]): AuditArgs {
	const out: AuditArgs = {
		help: false,
		subcommand: null,
		agent: null,
		user: null,
		from: null,
		to: null,
		json: false,
		db: null,
		error: null,
	};
	const [sub, ...rest] = args;
	if (sub === undefined || sub === "--help" || sub === "-h") {
		out.help = true;
		return out;
	}
	if (sub !== "verify" && sub !== "replay") {
		out.error = `Unknown audit command: ${sub}`;
		return out;
	}
	out.subcommand = sub;

	for (let i = 0; i < rest.length; i++) {
		const arg = rest[i] ?? "";
		const [flag, inline] = arg.includes("=")
			? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)]
			: [arg, undefined];
		const value = (): string | undefined => {
			if (inline !== undefined) return inline;
			i++;
			return rest[i];
		};
		switch (flag) {
			case "--help":
			case "-h":
				out.help = true;
				break;
			case "--json":
				out.json = true;
				break;
			case "--agent":
				out.agent = value() ?? null;
				break;
			case "--user":
				out.user = value() ?? null;
				break;
			case "--db":
				out.db = value() ?? null;
				break;
			case "--from":
			case "--since": {
				const r = parseDate(flag, value());
				if (r.error) out.error = r.error;
				out.from = r.date;
				break;
			}
			case "--to":
			case "--until": {
				const r = parseDate(flag, value());
				if (r.error) out.error = r.error;
				out.to = r.date;
				break;
			}
			default:
				out.error = `Unknown option: ${arg}`;
		}
		if (out.error) return out;
	}
	if (sub === "replay" && !out.agent) out.error = "replay needs --agent <id>";
	return out;
}

export interface AuditRunResult {
	code: number;
	output: string;
}

export async function runAudit(args: AuditArgs, audit: AuditModule): Promise<AuditRunResult> {
	if (args.subcommand === "replay" && args.agent) {
		const r = await audit.replayAgent(args.agent, {
			since: args.from ?? undefined,
			until: args.to ?? undefined,
			userId: args.user ?? undefined,
		});
		if (!r.success) return { code: 2, output: `Replay failed: ${r.error.message}\n` };
		const { events, verification } = r.data;
		const broken = verification.status === "broken";
		if (args.json) {
			return { code: broken ? 1 : 0, output: `${JSON.stringify(r.data, null, 2)}\n` };
		}
		const lines = events.map(
			(e) =>
				`${e.at.toISOString()}  ${e.kind.padEnd(10)} ${e.summary}${e.chained ? "" : "  [unchained]"}`,
		);
		lines.push(
			"",
			`Chain: ${verification.status} (${verification.checked} rows checked, ${verification.unchained} unchained)`,
		);
		if (verification.firstBreak) {
			lines.push(
				`First break: ${verification.firstBreak.reason} at seq ${verification.firstBreak.seq}, rows ${verification.firstBreak.rowIds.join(", ")}`,
			);
		}
		return { code: broken ? 1 : 0, output: `${lines.join("\n")}\n` };
	}

	const r = await audit.verifyAuditChain({
		agentId: args.agent ?? undefined,
		from: args.from ?? undefined,
		to: args.to ?? undefined,
	});
	if (!r.success) return { code: 2, output: `Verify failed: ${r.error.message}\n` };
	if (args.json) {
		return { code: r.data.ok ? 0 : 1, output: `${JSON.stringify(r.data, null, 2)}\n` };
	}
	if (r.data.ok) {
		return {
			code: 0,
			output: `OK: ${r.data.checked} chained rows verified, ${r.data.unchained} unchained rows skipped.\n`,
		};
	}
	const b = r.data.firstBreak;
	return {
		code: 1,
		output: `BROKEN: ${b?.reason} for agent ${b?.agentId} at seq ${b?.seq}. Rows: ${b?.rowIds.join(", ")}\n`,
	};
}

/** Open the database named by --db or DATABASE_URL and wrap it in an audit module. */
export async function openAuditModule(
	args: AuditArgs,
	env: NodeJS.ProcessEnv,
): Promise<{ audit: AuditModule } | { error: string }> {
	const url = args.db ?? env.DATABASE_URL;
	if (!url) return { error: "No database. Pass --db <url> or set DATABASE_URL." };
	const provider = /^postgres(ql)?:\/\//.test(url)
		? "postgres"
		: /^mysql:\/\//.test(url)
			? "mysql"
			: "sqlite-native";
	// Loaded on demand so parsing and --help never pull in the database drivers.
	const { createAuditModule, createDatabase } = await import("@glinr/theauth");
	const db = await createDatabase({ provider, url });
	return { audit: createAuditModule({ db, hmacKey: env.THEAUTH_AUDIT_HMAC_KEY }) };
}
