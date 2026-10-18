/**
 * `theauth audit verify` and `theauth audit replay`.
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
  theauth audit query [--agent <id>] [--user <id>] [--since <iso>] [--until <iso>] [--limit <n>]
                      [--provenance <kind>[:<hash>]] [--input-content <text>] [--json]
  theauth audit verify-go <export.json|export.ndjson> [--secret-hex <hex>] [--partial] [--json]
                          [--period-secrets <periods.json>]
                          [--head <head.json> --head-key <public-key.json>]

Options:
  --db <url>     Database URL (default: DATABASE_URL). postgres://, mysql://,
                 or a SQLite file path.
  --json         Machine readable output.

Environment:
  DATABASE_URL               Database to read.
  THEAUTH_AUDIT_HMAC_KEY     The audit.hmacKey the app runs with, if it sets one.

query lists audit rows. --provenance keeps rows that recorded an input of that kind
(user_message, tool_output, retrieved_document, agent) and, after the colon, with that
stored hash (64 lowercase hex), for example retrieved_document:3f2a... The hash is keyed
(HMAC under a key derived from the audit key), so to trace a piece of text use
--input-content "<text>" instead: the hash is computed with the audit key for you, and
plain hashes from older rows match too. Combine it with --provenance <kind> to narrow.
verify walks each agent's hash chain and prints the first broken link with the
row ids involved. It exits 1 when the chain is broken. replay prints one
agent's timeline (actions, decisions, delegations, approvals, token events)
and the chain verification status for that window. verify-go checks a chain
exported by theauth-go from a file (no database needed, see docs/audit-receipts).
With --head it also checks a signed head checkpoint (checkpoint.CreateHeadCheckpoint
in theauth-go) against the exported rows, which catches rows cut off the end of a
chain. --head-key is the Ed25519 public key file: {"keyId", "publicKey": {"kty",
"crv", "x"}}, a list of those, or {"keys": [...]}. The export must reach the signed
seq of every chain, so do not combine --head with a window that stops early.
--period-secrets is a JSON object {"<period>": "<hex secret>"} for the rotating
pseudonyms (r1:<period>:<hex>) theauth-go writes when audit pseudonym rotation is on.
A period missing from the file (shredded) is trusted as stored.
`;

export interface AuditArgs {
	help: boolean;
	subcommand: "verify" | "replay" | "verify-go" | "query" | null;
	file: string | null;
	secretHex: string | null;
	partial: boolean;
	periodSecrets: string | null;
	head: string | null;
	headKey: string | null;
	agent: string | null;
	user: string | null;
	from: Date | null;
	to: Date | null;
	json: boolean;
	db: string | null;
	limit: number | null;
	provenanceKind: string | null;
	provenanceHash: string | null;
	inputContent: string | null;
	error: string | null;
}

function parseDate(flag: string, value: string | undefined): { date: Date | null; error?: string } {
	if (value === undefined) return { date: null, error: `${flag} needs a value` };
	const date = new Date(value);
	if (Number.isNaN(date.getTime()))
		return { date: null, error: `${flag} is not a valid date: ${value}` };
	return { date };
}

const PROVENANCE_KINDS: readonly string[] = [
	"user_message",
	"tool_output",
	"retrieved_document",
	"agent",
];

export function parseAuditArgs(args: string[]): AuditArgs {
	const out: AuditArgs = {
		help: false,
		subcommand: null,
		file: null,
		secretHex: null,
		partial: false,
		periodSecrets: null,
		head: null,
		headKey: null,
		agent: null,
		user: null,
		from: null,
		to: null,
		json: false,
		db: null,
		limit: null,
		provenanceKind: null,
		provenanceHash: null,
		inputContent: null,
		error: null,
	};
	const [sub, ...rest] = args;
	if (sub === undefined || sub === "--help" || sub === "-h") {
		out.help = true;
		return out;
	}
	if (sub !== "verify" && sub !== "replay" && sub !== "verify-go" && sub !== "query") {
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
			case "--secret-hex":
				out.secretHex = value() ?? null;
				break;
			case "--period-secrets":
				out.periodSecrets = value() ?? null;
				if (!out.periodSecrets) out.error = "--period-secrets needs a file path";
				break;
			case "--head":
				out.head = value() ?? null;
				if (!out.head) out.error = "--head needs a file path";
				break;
			case "--head-key":
				out.headKey = value() ?? null;
				if (!out.headKey) out.error = "--head-key needs a file path";
				break;
			case "--partial":
				out.partial = true;
				break;
			case "--agent":
				out.agent = value() ?? null;
				break;
			case "--user":
				out.user = value() ?? null;
				break;
			case "--limit": {
				const n = Number(value());
				if (!Number.isInteger(n) || n < 1) out.error = "--limit must be a positive integer";
				else out.limit = n;
				break;
			}
			case "--input-content":
				out.inputContent = value() ?? null;
				if (!out.inputContent) out.error = "--input-content needs text";
				break;
			case "--provenance": {
				const raw = value() ?? "";
				const sep = raw.indexOf(":");
				const kind = sep === -1 ? raw : raw.slice(0, sep);
				const hash = sep === -1 ? "" : raw.slice(sep + 1);
				if (kind && !PROVENANCE_KINDS.includes(kind)) {
					out.error = `--provenance kind must be one of ${PROVENANCE_KINDS.join(", ")}`;
				} else if (hash && !/^[0-9a-f]{64}$/.test(hash)) {
					out.error = "--provenance hash must be 64 lowercase hex characters";
				} else if (!kind && !hash) {
					out.error = "--provenance needs <kind>, <kind>:<hash> or :<hash>";
				} else {
					out.provenanceKind = kind || null;
					out.provenanceHash = hash || null;
				}
				break;
			}
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
				if (sub === "verify-go" && !arg.startsWith("-") && out.file === null) out.file = arg;
				else out.error = `Unknown option: ${arg}`;
		}
		if (out.error) return out;
	}
	if (sub === "verify-go" && !out.file) out.error = "verify-go needs a file path";
	if (sub === "verify-go" && !out.error && (out.head === null) !== (out.headKey === null)) {
		out.error = "--head and --head-key go together";
	}
	if (sub === "replay" && !out.agent) out.error = "replay needs --agent <id>";
	return out;
}

export interface AuditRunResult {
	code: number;
	output: string;
}

async function runQuery(args: AuditArgs, audit: AuditModule): Promise<AuditRunResult> {
	const kind = args.provenanceKind;
	const hash = args.provenanceHash;
	const content = args.inputContent;
	const provenance =
		kind || hash || content
			? {
					...(kind ? { kind: kind as "user_message" } : {}),
					...(hash ? { hash } : {}),
					...(content ? { content } : {}),
				}
			: undefined;
	const rows = await audit.query({
		agentId: args.agent ?? undefined,
		userId: args.user ?? undefined,
		since: args.from ?? undefined,
		until: args.to ?? undefined,
		limit: args.limit ?? 50,
		...(provenance ? { provenance } : {}),
	});
	if (args.json) return { code: 0, output: `${JSON.stringify(rows, null, 2)}\n` };
	if (rows.length === 0) return { code: 0, output: "No matching rows.\n" };
	const lines = rows.map((r) => {
		const tags = r.inputs?.length
			? `  inputs: ${r.inputs.map((s) => (s.id ? `${s.kind}(${s.id})` : s.kind)).join(", ")}`
			: "";
		return `${r.timestamp.toISOString()}  ${r.result.padEnd(8)} ${r.agentId}  ${r.action} ${r.resource}${tags}`;
	});
	return { code: 0, output: `${lines.join("\n")}\n` };
}

export async function runAudit(args: AuditArgs, audit: AuditModule): Promise<AuditRunResult> {
	if (args.subcommand === "query") return runQuery(args, audit);
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
