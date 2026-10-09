/** Small RFC 4180 reader: quoted fields, doubled quotes, CRLF, embedded newlines. */
export function parseCsv(text: string): string[][] {
	const rows: string[][] = [];
	let row: string[] = [];
	let field = "";
	let inQuotes = false;
	const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
	for (let i = 0; i < src.length; i++) {
		const c = src[i] as string;
		if (inQuotes) {
			if (c === '"') {
				if (src[i + 1] === '"') {
					field += '"';
					i++;
				} else inQuotes = false;
			} else field += c;
		} else if (c === '"') inQuotes = true;
		else if (c === ",") {
			row.push(field);
			field = "";
		} else if (c === "\n" || c === "\r") {
			if (c === "\r" && src[i + 1] === "\n") i++;
			row.push(field);
			field = "";
			if (row.length > 1 || row[0] !== "") rows.push(row);
			row = [];
		} else field += c;
	}
	if (field !== "" || row.length > 0) {
		row.push(field);
		if (row.length > 1 || row[0] !== "") rows.push(row);
	}
	return rows;
}

/** Header row plus records keyed by header name. */
export function csvRecords(text: string): Record<string, string>[] {
	const rows = parseCsv(text);
	const header = rows[0];
	if (!header) return [];
	return rows.slice(1).map((r) => {
		const rec: Record<string, string> = {};
		header.forEach((h, idx) => {
			rec[h.trim()] = r[idx] ?? "";
		});
		return rec;
	});
}

/** JSON array, `{users: []}`, or newline-delimited JSON. */
export function parseJsonRecords(text: string): unknown[] {
	const trimmed = text.trim();
	if (trimmed === "") return [];
	try {
		const parsed: unknown = JSON.parse(trimmed);
		if (Array.isArray(parsed)) return parsed;
		if (parsed !== null && typeof parsed === "object") {
			const users = (parsed as Record<string, unknown>).users;
			if (Array.isArray(users)) return users;
			return [parsed];
		}
		return [];
	} catch {
		return trimmed
			.split(/\r?\n/)
			.filter((l) => l.trim() !== "")
			.map((l) => JSON.parse(l) as unknown);
	}
}

export function asRecord(v: unknown): Record<string, unknown> | null {
	return v !== null && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: null;
}

export function str(v: unknown): string | null {
	return typeof v === "string" && v !== "" ? v : null;
}

export function truthy(v: unknown): boolean {
	return v === true || v === 1 || v === "1" || (typeof v === "string" && /^(true|yes)$/i.test(v));
}
