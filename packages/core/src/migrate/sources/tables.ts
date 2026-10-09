import { asRecord, str, truthy } from "../csv.js";
import { bytesToBase64, detectHash } from "../hash-format.js";
import type { ImportedUser, LegacyHash, ParseIssue, ParseOutput, SourceParser } from "../types.js";

type Row = Record<string, unknown>;

function table(doc: Record<string, unknown>, ...names: string[]): Row[] {
	for (const n of names) {
		const v = doc[n];
		if (Array.isArray(v)) return v.map((r) => asRecord(r) ?? {});
	}
	return [];
}

function load(text: string): Record<string, unknown> | null {
	try {
		return asRecord(JSON.parse(text));
	} catch {
		return null;
	}
}

function fromHex(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

/**
 * Better Auth stores `saltHex:keyHex`, scrypt N=16384 r=16 p=1, key length 64,
 * with the hex salt string itself (UTF-8) used as the salt and NFKC-normalised passwords.
 */
function betterAuthHash(value: string): LegacyHash | null {
	const m = /^([0-9a-f]+):([0-9a-f]+)$/i.exec(value);
	if (!m) return detectHash(value);
	return {
		algorithm: "scrypt",
		hash: bytesToBase64(fromHex(m[2] as string)),
		salt: bytesToBase64(new TextEncoder().encode(m[1] as string)),
		params: { N: 16384, r: 16, p: 1, nfkc: true },
	};
}

function build(
	label: string,
	text: string,
	hashFor: (account: Row | undefined, user: Row) => LegacyHash | null,
	providerKeys: { provider: string; accountId: string },
	credentialProviders: string[],
): ParseOutput {
	const doc = load(text);
	if (!doc)
		return { users: [], issues: [{ row: 0, code: "INVALID_JSON", message: "not valid JSON" }] };
	const accounts = table(doc, "account", "accounts", "Account");
	const users: ImportedUser[] = [];
	const issues: ParseIssue[] = [];
	table(doc, "user", "users", "User").forEach((u, i) => {
		const id = str(u.id);
		const email = str(u.email)?.toLowerCase();
		if (!id || !email) {
			issues.push({
				row: i + 1,
				code: "MISSING_FIELD",
				message: `${label} user needs id and email`,
			});
			return;
		}
		const mine = accounts.filter((a) => (a.userId ?? a.user_id) === id);
		const cred = mine.find((a) =>
			credentialProviders.includes(String(a[providerKeys.provider] ?? "")),
		);
		const verified = u.emailVerified ?? u.email_verified;
		const user: ImportedUser = {
			externalId: id,
			email,
			emailVerified:
				verified instanceof Date ||
				(typeof verified === "string" && !/^(false|0)$/i.test(verified) && verified !== "") ||
				truthy(verified),
			name: str(u.name),
			linkedAccounts: mine
				.filter((a) => a !== cred)
				.flatMap((a) => {
					const provider = str(a[providerKeys.provider]);
					const pid = str(a[providerKeys.accountId]);
					return provider && pid ? [{ provider, providerAccountId: pid }] : [];
				}),
			metadata: { image: str(u.image) },
		};
		const hash = hashFor(cred, u);
		if (hash) user.passwordHash = hash;
		users.push(user);
	});
	return { users, issues };
}

export const betterAuthParser: SourceParser = {
	source: "better-auth",
	parse(text) {
		return build(
			"Better Auth",
			text,
			(account) => {
				const pw = str(account?.password);
				return pw ? betterAuthHash(pw) : null;
			},
			{ provider: "providerId", accountId: "accountId" },
			["credential"],
		);
	},
};

/** Auth.js adapter tables. There is no password column by default; a bcrypt `password` column on users is picked up when present. */
export const nextAuthParser: SourceParser = {
	source: "nextauth",
	parse(text) {
		return build(
			"Auth.js",
			text,
			(_account, user) => {
				const pw = str(user.password) ?? str(user.passwordHash) ?? str(user.hashedPassword);
				return pw ? detectHash(pw) : null;
			},
			{ provider: "provider", accountId: "providerAccountId" },
			["credentials"],
		);
	},
};
