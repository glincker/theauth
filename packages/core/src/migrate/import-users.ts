import { encodeLegacyHash } from "./hash-format.js";
import { getParser } from "./sources/index.js";
import type {
	ConflictPolicy,
	ImportedUser,
	ImportSource,
	MigrationStore,
	ParseIssue,
	ParseOptions,
	Result,
} from "./types.js";
import { err, ok } from "./types.js";

export type ImportInput =
	| string
	| Uint8Array
	| AsyncIterable<string | Uint8Array>
	| ReadableStream<Uint8Array>;

export type DiffAction = "create" | "skip" | "update" | "conflict" | "error";

/** One line of the dry-run diff. Carries the source id only, never email, name or hash. */
export interface DiffEntry {
	externalId: string | null;
	action: DiffAction;
	reason?: string;
	hasPassword?: boolean;
}

export interface ImportReport {
	source: ImportSource;
	dryRun: boolean;
	total: number;
	created: number;
	updated: number;
	skipped: number;
	conflicts: number;
	errors: number;
	withPasswordHash: number;
	withoutPasswordHash: number;
	issues: ParseIssue[];
	diff: DiffEntry[];
}

export interface ImportUsersOptions {
	source: ImportSource;
	stream: ImportInput;
	store: MigrationStore;
	/** Default true. Nothing is written until you pass false. */
	dryRun?: boolean;
	/** What to do when an email already belongs to a different account. Default "skip". */
	onConflict?: ConflictPolicy;
	batchSize?: number;
	maxBytes?: number;
	parseOptions?: ParseOptions;
	onProgress?: (done: number, total: number) => void;
}

const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

async function readAll(input: ImportInput, maxBytes: number): Promise<string | null> {
	const decoder = new TextDecoder();
	let out = "";
	let size = 0;
	const push = (chunk: string | Uint8Array): boolean => {
		size += typeof chunk === "string" ? chunk.length : chunk.byteLength;
		if (size > maxBytes) return false;
		out += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
		return true;
	};
	if (typeof input === "string" || input instanceof Uint8Array) {
		return push(input) ? out + decoder.decode() : null;
	}
	if ("getReader" in input) {
		const reader = input.getReader();
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!push(value)) {
				await reader.cancel();
				return null;
			}
		}
		return out + decoder.decode();
	}
	for await (const chunk of input) if (!push(chunk)) return null;
	return out + decoder.decode();
}

export async function importUsers(options: ImportUsersOptions): Promise<Result<ImportReport>> {
	const { source, store } = options;
	const dryRun = options.dryRun ?? true;
	const policy = options.onConflict ?? "skip";
	const batchSize = Math.max(1, options.batchSize ?? 500);
	let text: string | null;
	try {
		text = await readAll(options.stream, options.maxBytes ?? DEFAULT_MAX_BYTES);
	} catch {
		return err("READ_FAILED", "Could not read the export");
	}
	if (text === null) return err("TOO_LARGE", "Export exceeds maxBytes");

	let parsed: { users: ImportedUser[]; issues: ParseIssue[] };
	try {
		parsed = getParser(source).parse(text, options.parseOptions);
	} catch {
		return err("PARSE_FAILED", `Could not parse the ${source} export`);
	}

	const report: ImportReport = {
		source,
		dryRun,
		total:
			parsed.users.length +
			parsed.issues.filter((i) => i.code === "MISSING_FIELD" || i.code === "INVALID_JSON").length,
		created: 0,
		updated: 0,
		skipped: 0,
		conflicts: 0,
		errors: parsed.issues.filter((i) => i.code === "MISSING_FIELD" || i.code === "INVALID_JSON")
			.length,
		withPasswordHash: 0,
		withoutPasswordHash: 0,
		issues: parsed.issues,
		diff: [],
	};
	for (const i of parsed.issues) {
		if (i.code === "MISSING_FIELD" || i.code === "INVALID_JSON") {
			report.diff.push({ externalId: null, action: "error", reason: i.code });
		}
	}

	const seen = new Set<string>();
	const seenEmails = new Set<string>();
	let done = 0;
	for (let start = 0; start < parsed.users.length; start += batchSize) {
		for (const user of parsed.users.slice(start, start + batchSize)) {
			const entry = await processUser(user, seen, seenEmails);
			report.diff.push(entry);
			if (entry.action === "create") report.created++;
			else if (entry.action === "update") report.updated++;
			else if (entry.action === "skip") report.skipped++;
			else if (entry.action === "conflict") report.conflicts++;
			else report.errors++;
			if (user.passwordHash) report.withPasswordHash++;
			else report.withoutPasswordHash++;
			if (entry.action === "conflict" && policy === "fail") {
				return {
					success: false,
					error: {
						code: "CONFLICT",
						message: "Stopped on the first conflict (onConflict: fail)",
						details: { created: report.created, externalId: user.externalId },
					},
				};
			}
		}
		done = Math.min(parsed.users.length, start + batchSize);
		options.onProgress?.(done, parsed.users.length);
	}
	return ok(report);

	async function processUser(
		user: ImportedUser,
		ids: Set<string>,
		emails: Set<string>,
	): Promise<DiffEntry> {
		const base = { externalId: user.externalId, hasPassword: user.passwordHash !== undefined };
		try {
			if (ids.has(user.externalId))
				return { ...base, action: "skip", reason: "DUPLICATE_IN_EXPORT" };
			ids.add(user.externalId);
			const existing = await store.findBySourceId(source, user.externalId);
			if (existing) return { ...base, action: "skip", reason: "ALREADY_IMPORTED" };
			const byEmail = emails.has(user.email)
				? { id: "in-export" }
				: await store.findByEmail(user.email);
			emails.add(user.email);
			if (byEmail) {
				if (policy === "update" && byEmail.id !== "in-export") {
					if (!dryRun) await store.updateUser(byEmail.id, user);
					return { ...base, action: "update", reason: "EMAIL_ADOPTED" };
				}
				return { ...base, action: "conflict", reason: "EMAIL_EXISTS" };
			}
			if (!dryRun) {
				const created = await store.createUser(user, source);
				if (user.passwordHash)
					await store.setPasswordHash(created.id, encodeLegacyHash(user.passwordHash));
				await store.recordMigration({
					userId: created.id,
					source,
					status: "pending",
					cohort: null,
					errorCode: null,
					at: new Date(),
				});
			}
			return { ...base, action: "create" };
		} catch {
			return { ...base, action: "error", reason: "STORE_FAILED" };
		}
	}
}
