import { asRecord, csvRecords, parseJsonRecords, str, truthy } from "../csv.js";
import { detectHash } from "../hash-format.js";
import type { ImportedUser, ParseIssue, ParseOutput, SourceParser } from "../types.js";

/** Any CSV or JSON file, with a column or field name mapping. */
export const genericParser: SourceParser = {
	source: "generic",
	parse(text, options): ParseOutput {
		const m = options?.mapping ?? {};
		const t = text.trimStart();
		const rows: Record<string, unknown>[] =
			t.startsWith("[") || t.startsWith("{")
				? parseJsonRecords(text).map((r) => asRecord(r) ?? {})
				: csvRecords(text);
		const users: ImportedUser[] = [];
		const issues: ParseIssue[] = [];
		rows.forEach((rec, i) => {
			const email = str(rec[m.email ?? "email"])?.toLowerCase();
			const id = str(rec[m.externalId ?? "id"]) ?? email;
			if (!email || !id) {
				issues.push({ row: i + 1, code: "MISSING_FIELD", message: "email is required" });
				return;
			}
			const user: ImportedUser = {
				externalId: id,
				email,
				emailVerified: truthy(rec[m.emailVerified ?? "email_verified"]),
				name: str(rec[m.name ?? "name"]),
				linkedAccounts: [],
				metadata: {},
			};
			const raw = str(rec[m.passwordHash ?? "password_hash"]);
			if (raw) {
				const detected = detectHash(raw);
				if (detected) user.passwordHash = detected;
				else
					issues.push({
						row: i + 1,
						code: "UNSUPPORTED_HASH",
						message: "hash format not recognised (bcrypt and argon2 are auto-detected)",
					});
			}
			users.push(user);
		});
		return { users, issues };
	},
};
