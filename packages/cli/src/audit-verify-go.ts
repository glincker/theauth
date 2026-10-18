/** `theauth audit verify-go <file>`: verify a hash chain exported by theauth-go. Reads a file only. */

import { readFile } from "node:fs/promises";
import type { GoAuditRow } from "@glinr/theauth";
import { verifyGoAuditChain } from "@glinr/theauth";
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

export async function runVerifyGo(args: AuditArgs): Promise<AuditRunResult> {
	let r: Awaited<ReturnType<typeof verifyGoAuditChain>>;
	try {
		const rows = parseGoExport(await readFile(args.file ?? "", "utf8"));
		r = await verifyGoAuditChain(rows, {
			pseudonymSecret: args.secretHex ?? undefined,
			allowPartialStart: args.partial,
		});
	} catch (e) {
		return {
			code: 2,
			output: `Cannot verify export: ${e instanceof Error ? e.message : "unknown"}\n`,
		};
	}
	if (args.json) return { code: r.ok ? 0 : 1, output: `${JSON.stringify(r, null, 2)}\n` };
	if (r.ok) {
		return {
			code: 0,
			output: `OK: ${r.checked} rows in ${r.chains} chain(s) verified, ${r.erased} erased, ${r.unchained} unchained skipped.\n`,
		};
	}
	const f = r.firstFailure;
	return {
		code: 1,
		output: `BROKEN: ${f?.reason} in chain "${f?.chainKey}" at seq ${f?.seq} (row ${f?.rowId}, index ${f?.index}).\n`,
	};
}
