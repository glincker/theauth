/**
 * `theauth migrate plan | import | verify | status`.
 *
 * Own file so bin.ts needs one import and one switch case. Output never contains
 * emails, names or hashes: only counts, source ids in the diff, and error codes.
 */

import { readFileSync, writeFileSync } from "node:fs";
import type { ImportReport, ImportSource, MigrationStore } from "@glinr/theauth/migrate";

export const MIGRATE_HELP = `
theauth migrate

Move users from another auth system without a rewrite.

Usage:
  theauth migrate plan   --from <source> <export> [--hashes <file>] [--json]
  theauth migrate import --from <source> <export> [--hashes <file>] [--db <url>] [--apply] [--on-conflict skip|update|fail]
  theauth migrate verify --from <source> <export> [--hashes <file>] [--db <url>] [--sample-email <email>]
  theauth migrate status [--db <url>] [--json] [--out <file>]

Sources: auth0, keycloak, clerk, better-auth, nextauth, generic

Options:
  --hashes <file>    Auth0 only: the password hash export (newline-delimited JSON).
  --map k=v,...      generic only: externalId=,email=,emailVerified=,name=,passwordHash=
  --db <url>         SQLite file path or :memory: (default: DATABASE_URL).
  --apply            import only: write. Without it import is a dry run.
  --sample-email     verify only: check one login. Set THEAUTH_MIGRATE_PASSWORD first.
  --json             Machine readable output.

plan never touches a database. import is a dry run until you pass --apply.
Reports contain counts and source ids only, never emails, names or hashes.
`;

export interface MigrateArgs {
	help: boolean;
	subcommand: "plan" | "import" | "verify" | "status" | null;
	from: ImportSource | null;
	file: string | null;
	hashes: string | null;
	db: string | null;
	apply: boolean;
	onConflict: "skip" | "update" | "fail";
	sampleEmail: string | null;
	map: Record<string, string>;
	json: boolean;
	out: string | null;
	error: string | null;
}

const SOURCES: readonly string[] = [
	"auth0",
	"keycloak",
	"clerk",
	"better-auth",
	"nextauth",
	"generic",
];
const SUBS = ["plan", "import", "verify", "status"] as const;

export function parseMigrateArgs(args: string[]): MigrateArgs {
	const out: MigrateArgs = {
		help: false,
		subcommand: null,
		from: null,
		file: null,
		hashes: null,
		db: null,
		apply: false,
		onConflict: "skip",
		sampleEmail: null,
		map: {},
		json: false,
		out: null,
		error: null,
	};
	const [sub, ...rest] = args;
	if (sub === undefined || sub === "--help" || sub === "-h") {
		out.help = true;
		return out;
	}
	const found = SUBS.find((s) => s === sub);
	if (!found) {
		out.error = `Unknown migrate command: ${sub}`;
		return out;
	}
	out.subcommand = found;
	for (let i = 0; i < rest.length; i++) {
		const arg = rest[i] ?? "";
		const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
		const flag = eq >= 0 ? arg.slice(0, eq) : arg;
		const inline = eq >= 0 ? arg.slice(eq + 1) : undefined;
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
			case "--apply":
				out.apply = true;
				break;
			case "--from": {
				const v = value();
				if (v && SOURCES.includes(v)) out.from = v as ImportSource;
				else out.error = `--from must be one of ${SOURCES.join(", ")}`;
				break;
			}
			case "--hashes":
				out.hashes = value() ?? null;
				break;
			case "--db":
				out.db = value() ?? null;
				break;
			case "--out":
				out.out = value() ?? null;
				break;
			case "--sample-email":
				out.sampleEmail = value() ?? null;
				break;
			case "--on-conflict": {
				const v = value();
				if (v === "skip" || v === "update" || v === "fail") out.onConflict = v;
				else out.error = "--on-conflict must be skip, update or fail";
				break;
			}
			case "--map":
				for (const pair of (value() ?? "").split(",")) {
					const [k, v] = pair.split("=");
					if (k && v) out.map[k] = v;
				}
				break;
			default:
				if (arg.startsWith("-")) out.error = `Unknown option: ${arg}`;
				else out.file = arg;
		}
		if (out.error) return out;
	}
	if (found !== "status" && !out.help) {
		if (!out.from) out.error = "--from <source> is required";
		else if (!out.file) out.error = "An export file path is required";
	}
	return out;
}

export interface MigrateRunResult {
	code: number;
	output: string;
}

function formatReport(r: ImportReport, gaps: string[]): string {
	const lines = [
		`${r.dryRun ? "Dry run" : "Import"} from ${r.source}`,
		`  records ${r.total}, would create ${r.created}, update ${r.updated}, skip ${r.skipped}, conflicts ${r.conflicts}, errors ${r.errors}`,
		`  with password hash ${r.withPasswordHash}, without ${r.withoutPasswordHash}`,
	];
	const codes = new Map<string, number>();
	for (const i of r.issues) codes.set(i.code, (codes.get(i.code) ?? 0) + 1);
	for (const [code, n] of codes) lines.push(`  issue ${code}: ${n}`);
	if (gaps.length > 0) {
		lines.push("Gaps:");
		for (const g of gaps) lines.push(`  ${g}`);
	}
	if (r.dryRun) lines.push("Nothing was written.");
	return `${lines.join("\n")}\n`;
}

const GAP_NOTES: Record<string, string> = {
	bcrypt:
		"bcrypt hashes verify on first login if you pass verifiers.bcrypt (for example bcryptjs). Without it those users reset their password.",
	argon2:
		"argon2 hashes need verifiers.argon2 (for example @node-rs/argon2). Without it those users reset their password.",
};

export async function runMigrate(
	args: MigrateArgs,
	env: NodeJS.ProcessEnv,
): Promise<MigrateRunResult> {
	const lib = await import("@glinr/theauth/migrate");
	if (args.subcommand === "status") return runStatus(args, env, lib);

	let text: string;
	let hashesText: string | undefined;
	try {
		text = readFileSync(args.file as string, "utf-8");
		if (args.hashes) hashesText = readFileSync(args.hashes, "utf-8");
	} catch {
		return { code: 2, output: "Could not read the export file.\n" };
	}
	const source = args.from as ImportSource;
	const parseOptions = { passwordHashes: hashesText, mapping: args.map };

	const parsed = lib.getParser(source).parse(text, parseOptions);
	const algos = new Map<string, number>();
	for (const u of parsed.users) {
		if (u.passwordHash)
			algos.set(u.passwordHash.algorithm, (algos.get(u.passwordHash.algorithm) ?? 0) + 1);
	}
	const gaps = [...algos.keys()].flatMap((a) => (GAP_NOTES[a] ? [GAP_NOTES[a] as string] : []));

	if (args.subcommand === "plan") {
		const store = lib.createMemoryMigrationStore();
		const r = await lib.importUsers({ source, stream: text, store, dryRun: true, parseOptions });
		if (!r.success) return { code: 1, output: `Plan failed: ${r.error.message}\n` };
		if (args.json) {
			return {
				code: 0,
				output: `${JSON.stringify({ report: r.data, algorithms: Object.fromEntries(algos), gaps }, null, 2)}\n`,
			};
		}
		const algoLine = [...algos].map(([a, n]) => `${a} ${n}`).join(", ");
		return {
			code: 0,
			output: `${formatReport(r.data, gaps)}  hash algorithms: ${algoLine || "none"}\n`,
		};
	}

	const opened = await openStore(args, env, lib);
	if ("error" in opened) return { code: 2, output: `${opened.error}\n` };
	const store = opened.store;

	if (args.subcommand === "import") {
		const r = await lib.importUsers({
			source,
			stream: text,
			store,
			dryRun: !args.apply,
			onConflict: args.onConflict,
			parseOptions,
		});
		if (!r.success)
			return { code: 1, output: `Import stopped: ${r.error.code}, ${r.error.message}\n` };
		const body = args.json ? `${JSON.stringify(r.data, null, 2)}\n` : formatReport(r.data, gaps);
		return { code: r.data.errors > 0 ? 1 : 0, output: body };
	}

	return runVerify(
		args,
		env,
		lib,
		store,
		parsed.users.map((u) => u.externalId),
	);
}

type Lib = typeof import("@glinr/theauth/migrate");

async function openStore(
	args: MigrateArgs,
	env: NodeJS.ProcessEnv,
	lib: Lib,
): Promise<{ store: MigrationStore } | { error: string }> {
	const url = args.db ?? env.DATABASE_URL;
	if (!url) return { error: "No database. Pass --db <url> or set DATABASE_URL." };
	if (/^(postgres(ql)?|mysql):\/\//.test(url)) {
		return {
			error:
				"The CLI store supports SQLite for now. For Postgres or MySQL, run importUsers from a script with your own MigrationStore.",
		};
	}
	const core = await import("@glinr/theauth");
	const db = await core.createDatabase({ provider: "sqlite-native", url });
	await core.createTables(db, "sqlite");
	return { store: await lib.createDbMigrationStore(db) };
}

async function runVerify(
	args: MigrateArgs,
	env: NodeJS.ProcessEnv,
	lib: Lib,
	store: MigrationStore,
	ids: string[],
): Promise<MigrateRunResult> {
	let present = 0;
	for (const id of ids) if (await store.findBySourceId(args.from as string, id)) present++;
	const lines = [
		`Export has ${ids.length} users, ${present} found in the database, ${ids.length - present} missing.`,
	];
	let code = ids.length === present ? 0 : 1;
	if (args.sampleEmail) {
		const password = env.THEAUTH_MIGRATE_PASSWORD;
		const user = await store.findByEmail(args.sampleEmail);
		const stored = user ? await store.getPasswordHash(user.id) : null;
		if (!password) {
			lines.push("Sample login: set THEAUTH_MIGRATE_PASSWORD to the sample user's password.");
			code = 1;
		} else if (!stored) {
			lines.push("Sample login: user or password hash not found.");
			code = 1;
		} else {
			const legacy = lib.decodeLegacyHash(stored);
			const checked = legacy
				? await lib.verifyLegacyHash(password, legacy)
				: ({
						success: false,
						error: { code: "NATIVE_HASH", message: "already migrated" },
					} as const);
			if (checked.success)
				lines.push(`Sample login: ${checked.data ? "password accepted" : "password rejected"}.`);
			else lines.push(`Sample login: not checked (${checked.error.code}).`);
			if (!checked.success || !checked.data) code = checked.success ? 1 : code;
		}
	}
	return { code, output: `${lines.join("\n")}\n` };
}

async function runStatus(
	args: MigrateArgs,
	env: NodeJS.ProcessEnv,
	lib: Lib,
): Promise<MigrateRunResult> {
	const opened = await openStore(args, env, lib);
	if ("error" in opened) return { code: 2, output: `${opened.error}\n` };
	const report = await lib.getMigrationStatus(opened.store);
	if (args.out) {
		try {
			writeFileSync(args.out, `${JSON.stringify(report, null, 2)}\n`);
		} catch {
			return { code: 2, output: "Could not write the report file.\n" };
		}
	}
	return {
		code: 0,
		output: args.json ? `${JSON.stringify(report, null, 2)}\n` : lib.formatStatus(report),
	};
}
