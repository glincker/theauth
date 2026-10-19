/** `theauth audit verify-go <file>`: verify a hash chain exported by theauth-go. Reads files only. */

import { readFile } from "node:fs/promises";
import type { CheckpointPublicKey, GoAuditRow, GoHeadResult } from "@glinr/theauth";
import { verifyGoAuditChain, verifyGoHeadCheckpoint } from "@glinr/theauth";
import type { AuditArgs, AuditRunResult } from "./audit-commands.js";

/** Accepts a JSON array, an object with a `rows` or `events` array, or NDJSON (one row per line). */
export function parseGoExport(text: string): GoAuditRow[] {
	const trimmed = text.trim();
	if (trimmed.startsWith("[") || (trimmed.startsWith("{") && !trimmed.includes("\n{"))) {
		const doc = JSON.parse(trimmed) as unknown;
		if (Array.isArray(doc)) return doc as GoAuditRow[];
		const o = doc as { rows?: unknown; events?: unknown };
		const list = Array.isArray(o.rows) ? o.rows : o.events;
		if (Array.isArray(list)) return list as GoAuditRow[];
		return [doc as GoAuditRow];
	}
	return trimmed
		.split("\n")
		.filter((l) => l.trim() !== "")
		.map((l) => JSON.parse(l) as GoAuditRow);
}

/** Reads a public key file: one key, a list of keys, or `{"keys": [...]}`. */
export function parseHeadKeys(text: string): CheckpointPublicKey[] {
	const doc = JSON.parse(text) as unknown;
	const list = Array.isArray(doc)
		? doc
		: Array.isArray((doc as { keys?: unknown } | null)?.keys)
			? (doc as { keys: unknown[] }).keys
			: [doc];
	const keys = list.filter(
		(k): k is CheckpointPublicKey =>
			typeof k === "object" &&
			k !== null &&
			typeof (k as CheckpointPublicKey).keyId === "string" &&
			typeof (k as CheckpointPublicKey).publicKey === "object" &&
			(k as CheckpointPublicKey).publicKey !== null,
	);
	if (keys.length === 0) throw new Error("no public key with keyId and publicKey found");
	return keys;
}

export async function runVerifyGo(args: AuditArgs): Promise<AuditRunResult> {
	let r: Awaited<ReturnType<typeof verifyGoAuditChain>>;
	let head: GoHeadResult | null = null;
	try {
		const rows = parseGoExport(await readFile(args.file ?? "", "utf8"));
		const periodSecrets =
			args.periodSecrets === null
				? undefined
				: (JSON.parse(await readFile(args.periodSecrets, "utf8")) as Record<string, string>);
		r = await verifyGoAuditChain(rows, {
			pseudonymSecret: args.secretHex ?? undefined,
			periodSecrets,
			allowPartialStart: args.partial,
		});
		if (args.head !== null && args.headKey !== null) {
			const checkpoint = JSON.parse(await readFile(args.head, "utf8")) as unknown;
			const keys = parseHeadKeys(await readFile(args.headKey, "utf8"));
			head = await verifyGoHeadCheckpoint(checkpoint, keys, rows);
		}
	} catch (e) {
		return {
			code: 2,
			output: `Cannot verify export: ${e instanceof Error ? e.message : "unknown"}\n`,
		};
	}
	const headOk = head === null || head.valid;
	const code = r.ok && headOk ? 0 : 1;
	if (args.json) {
		return { code, output: `${JSON.stringify(head === null ? r : { ...r, head }, null, 2)}\n` };
	}
	let out = "";
	if (r.ok) {
		out += `OK: ${r.checked} rows in ${r.chains} chain(s) verified, ${r.erased} erased, ${r.unchained} unchained skipped.\n`;
	} else {
		const f = r.firstFailure;
		out += `BROKEN: ${f?.reason} in chain "${f?.chainKey}" at seq ${f?.seq} (row ${f?.rowId}, index ${f?.index}).\n`;
	}
	if (head !== null) {
		if (head.valid) {
			out +=
				"OK: head checkpoint signature is valid and every signed chain head is in the export.\n";
		} else if (head.chainKey === undefined) {
			out += `BROKEN: head checkpoint ${head.reason}.\n`;
		} else {
			out += `BROKEN: head checkpoint ${head.reason} in chain "${head.chainKey}".\n`;
		}
	}
	return { code, output: out };
}
