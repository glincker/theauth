import { asRecord, parseJsonRecords, str, truthy } from "../csv.js";
import { detectHash } from "../hash-format.js";
import type { ImportedUser, LegacyHash, ParseIssue, ParseOutput, SourceParser } from "../types.js";

/** `GET /user_management/users` pages look like `{object: "list", data: [...]}`. Unwrap them. */
function users(text: string): unknown[] {
	return parseJsonRecords(text).flatMap((raw) => {
		const rec = asRecord(raw);
		return rec && Array.isArray(rec.data) ? rec.data : [raw];
	});
}

function hashesByEmail(text: string | undefined): Map<string, LegacyHash> {
	const map = new Map<string, LegacyHash>();
	if (!text) return map;
	for (const raw of parseJsonRecords(text)) {
		const rec = asRecord(raw);
		const email = str(rec?.email)?.toLowerCase();
		const hash = str(rec?.passwordHash);
		const detected = hash ? detectHash(hash) : null;
		if (email && detected) map.set(email, detected);
	}
	return map;
}

/**
 * WorkOS AuthKit users, as returned by the List users API (`GET /user_management/users`), one page
 * per file, an array, or newline-delimited JSON. Fields follow the User object:
 * https://workos.com/docs/reference/authkit/user
 *
 * The API never returns password hashes, and WorkOS documents hash import only. If WorkOS support
 * gives you a hash file, pass it as `passwordHashes` (same newline-delimited format as the Auth0
 * source: `{"email": "...", "passwordHash": "..."}`). Only bcrypt and argon2 are importable.
 */
export const workosParser: SourceParser = {
	source: "workos",
	parse(text, options): ParseOutput {
		const hashes = hashesByEmail(options?.passwordHashes);
		const out: ImportedUser[] = [];
		const issues: ParseIssue[] = [];
		users(text).forEach((raw, i) => {
			const rec = asRecord(raw);
			const id = str(rec?.id);
			const email = str(rec?.email)?.toLowerCase();
			if (!rec || !id || !email) {
				issues.push({ row: i + 1, code: "MISSING_FIELD", message: "id and email are required" });
				return;
			}
			const joined = [str(rec.first_name), str(rec.last_name)].filter(Boolean).join(" ");
			const user: ImportedUser = {
				externalId: id,
				email,
				emailVerified: truthy(rec.email_verified),
				name: str(rec.name) ?? (joined === "" ? null : joined),
				linkedAccounts: [],
				metadata: {
					external_id: str(rec.external_id),
					metadata: asRecord(rec.metadata) ?? {},
					locale: str(rec.locale),
				},
			};
			const hash = hashes.get(email);
			if (hash) user.passwordHash = hash;
			out.push(user);
		});
		return { users: out, issues };
	},
};
