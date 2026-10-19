import { asRecord, csvRecords, parseJsonRecords, str } from "../csv.js";
import { detectHash } from "../hash-format.js";
import type {
	ImportedUser,
	LinkedAccount,
	ParseIssue,
	ParseOutput,
	SourceParser,
} from "../types.js";

/** A JSON column arrives as an object from a JSON export and as a string from a CSV export. */
function jsonColumn(v: unknown): Record<string, unknown> {
	if (typeof v === "string") {
		try {
			return asRecord(JSON.parse(v)) ?? {};
		} catch {
			return {};
		}
	}
	return asRecord(v) ?? {};
}

function records(text: string): Record<string, unknown>[] {
	const t = text.trimStart();
	if (t.startsWith("[") || t.startsWith("{")) {
		return parseJsonRecords(text).map((r) => asRecord(r) ?? {});
	}
	return csvRecords(text);
}

function identityOf(rec: Record<string, unknown>): LinkedAccount | null {
	const provider = str(rec.provider);
	const providerId = str(rec.provider_id);
	// The "email" and "phone" identities are the password and OTP logins, not linked accounts.
	if (!provider || !providerId || provider === "email" || provider === "phone") return null;
	return { provider, providerAccountId: providerId };
}

/**
 * Supabase Auth, read from the `auth.users` table.
 *
 * Input is rows of `auth.users`, as JSON (`select json_agg(u) ...`) or as CSV from the SQL editor.
 * Two shapes are accepted: one row per user, or the `LEFT JOIN auth.identities` shape with one row
 * per user and identity (columns `provider`, `provider_id`), which is merged by user id. A nested
 * `identities` array on a row also works. Supabase stores bcrypt in `encrypted_password`.
 * Docs: https://supabase.com/docs/guides/auth/managing-user-data and the `auth` schema.
 */
export const supabaseParser: SourceParser = {
	source: "supabase",
	parse(text): ParseOutput {
		const issues: ParseIssue[] = [];
		const byId = new Map<string, { user: ImportedUser; seen: Set<string> }>();
		records(text).forEach((rec, i) => {
			const id = str(rec.id);
			const email = str(rec.email)?.toLowerCase();
			if (!id || !email) {
				issues.push({
					row: i + 1,
					code: "MISSING_FIELD",
					message: "id and email are required",
				});
				return;
			}
			let entry = byId.get(id);
			if (!entry) {
				const meta = jsonColumn(rec.raw_user_meta_data);
				const verifiedAt = str(rec.email_confirmed_at) ?? str(rec.confirmed_at);
				const user: ImportedUser = {
					externalId: id,
					email,
					emailVerified:
						verifiedAt !== null || rec.email_verified === true || rec.email_verified === "true",
					name: str(meta.full_name) ?? str(meta.name) ?? str(rec.full_name) ?? str(rec.name),
					linkedAccounts: [],
					metadata: {
						user_metadata: meta,
						app_metadata: jsonColumn(rec.raw_app_meta_data),
						phone: str(rec.phone),
					},
				};
				const digest = str(rec.encrypted_password);
				if (digest) {
					const detected = detectHash(digest);
					if (detected) user.passwordHash = detected;
					else {
						issues.push({
							row: i + 1,
							code: "UNSUPPORTED_HASHER",
							message: "encrypted_password is not bcrypt or argon2",
						});
					}
				}
				entry = { user, seen: new Set() };
				byId.set(id, entry);
			}
			const found: (LinkedAccount | null)[] = [identityOf(rec)];
			if (Array.isArray(rec.identities)) {
				for (const x of rec.identities) found.push(identityOf(asRecord(x) ?? {}));
			}
			for (const link of found) {
				if (!link) continue;
				const key = `${link.provider}:${link.providerAccountId}`;
				if (entry.seen.has(key)) continue;
				entry.seen.add(key);
				entry.user.linkedAccounts.push(link);
			}
		});
		return { users: [...byId.values()].map((e) => e.user), issues };
	},
};
