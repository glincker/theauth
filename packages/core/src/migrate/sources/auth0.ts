import { asRecord, parseJsonRecords, str, truthy } from "../csv.js";
import { detectHash } from "../hash-format.js";
import type { ImportedUser, LegacyHash, ParseIssue, ParseOutput, SourceParser } from "../types.js";

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
 * Auth0 user export (Management API bulk export JSON) with the optional password
 * hash export Auth0 support provides (newline-delimited JSON, bcrypt hashes).
 */
export const auth0Parser: SourceParser = {
	source: "auth0",
	parse(text, options): ParseOutput {
		const hashes = hashesByEmail(options?.passwordHashes);
		const users: ImportedUser[] = [];
		const issues: ParseIssue[] = [];
		parseJsonRecords(text).forEach((raw, i) => {
			const rec = asRecord(raw);
			const id = str(rec?.user_id);
			const email = str(rec?.email)?.toLowerCase();
			if (!rec || !id || !email) {
				issues.push({
					row: i + 1,
					code: "MISSING_FIELD",
					message: "user_id and email are required",
				});
				return;
			}
			const identities = Array.isArray(rec.identities) ? rec.identities : [];
			const linked = identities.flatMap((x) => {
				const ident = asRecord(x);
				const provider = str(ident?.provider);
				const pid = ident?.user_id === undefined ? null : String(ident.user_id);
				if (!ident || !provider || !pid || provider === "auth0") return [];
				return [{ provider, providerAccountId: pid }];
			});
			const user: ImportedUser = {
				externalId: id,
				email,
				emailVerified: truthy(rec.email_verified),
				name: str(rec.name),
				linkedAccounts: linked,
				metadata: {
					user_metadata: asRecord(rec.user_metadata) ?? {},
					app_metadata: asRecord(rec.app_metadata) ?? {},
				},
			};
			const hash = hashes.get(email);
			if (hash) user.passwordHash = hash;
			users.push(user);
		});
		return { users, issues };
	},
};
