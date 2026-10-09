import { asRecord, csvRecords, parseJsonRecords, str } from "../csv.js";
import { detectHash } from "../hash-format.js";
import type { ImportedUser, ParseIssue, ParseOutput, SourceParser } from "../types.js";

function records(text: string): Record<string, unknown>[] {
	const t = text.trimStart();
	if (t.startsWith("[") || t.startsWith("{")) {
		return parseJsonRecords(text).map((r) => asRecord(r) ?? {});
	}
	return csvRecords(text);
}

function list(v: unknown): string[] {
	if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
	if (typeof v === "string")
		return v
			.split(/[,;|]/)
			.map((s) => s.trim())
			.filter(Boolean);
	return [];
}

/** Clerk dashboard export (CSV) or Backend API users (JSON). Only bcrypt digests are importable. */
export const clerkParser: SourceParser = {
	source: "clerk",
	parse(text): ParseOutput {
		const users: ImportedUser[] = [];
		const issues: ParseIssue[] = [];
		records(text).forEach((rec, i) => {
			const id = str(rec.id) ?? str(rec.user_id);
			const email = (
				str(rec.primary_email_address) ??
				list(rec.email_addresses)[0] ??
				null
			)?.toLowerCase();
			if (!id || !email) {
				issues.push({
					row: i + 1,
					code: "MISSING_FIELD",
					message: "id and primary email are required",
				});
				return;
			}
			const verified = list(rec.verified_email_addresses).map((e) => e.toLowerCase());
			const name = [str(rec.first_name), str(rec.last_name)].filter(Boolean).join(" ");
			const user: ImportedUser = {
				externalId: id,
				email,
				emailVerified: verified.includes(email),
				name: name === "" ? str(rec.username) : name,
				linkedAccounts: [],
				metadata: { username: str(rec.username) },
			};
			const digest = str(rec.password_digest);
			if (digest) {
				const hasher = str(rec.password_hasher);
				const detected = detectHash(digest);
				if (detected && (!hasher || hasher === "bcrypt" || hasher.startsWith("argon2"))) {
					user.passwordHash = detected;
				} else {
					issues.push({
						row: i + 1,
						code: "UNSUPPORTED_HASHER",
						message: `hasher ${hasher ?? "unknown"} is not importable`,
					});
				}
			}
			users.push(user);
		});
		return { users, issues };
	},
};
