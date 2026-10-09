import { asRecord, str, truthy } from "../csv.js";
import type {
	ImportedUser,
	LegacyAlgorithm,
	LegacyHash,
	ParseIssue,
	ParseOutput,
	SourceParser,
} from "../types.js";

function jsonField(v: unknown): Record<string, unknown> | null {
	if (typeof v === "string") {
		try {
			return asRecord(JSON.parse(v));
		} catch {
			return null;
		}
	}
	return asRecord(v);
}

const ALGOS: Record<string, LegacyAlgorithm> = {
	"pbkdf2-sha256": "pbkdf2-sha256",
	"pbkdf2-sha512": "pbkdf2-sha512",
	pbkdf2: "pbkdf2-sha1",
	"pbkdf2-sha1": "pbkdf2-sha1",
};

/** Handles both the current (secretData/credentialData) and the pre 8.x credential shapes. */
function credentialHash(cred: Record<string, unknown>): LegacyHash | null {
	const secret = jsonField(cred.secretData);
	const data = jsonField(cred.credentialData);
	const value = str(secret?.value) ?? str(cred.hashedSaltedValue);
	const salt = str(secret?.salt) ?? str(cred.salt);
	const algoName = str(data?.algorithm) ?? str(cred.algorithm) ?? "pbkdf2-sha256";
	const iterations = Number(data?.hashIterations ?? cred.hashIterations ?? 0);
	const algorithm = ALGOS[algoName];
	if (!value || !salt || !algorithm || !Number.isFinite(iterations) || iterations <= 0) return null;
	return { algorithm, hash: value, salt, params: { iterations } };
}

/** Keycloak realm export: `users[]` with credentials and federated identities. */
export const keycloakParser: SourceParser = {
	source: "keycloak",
	parse(text): ParseOutput {
		const users: ImportedUser[] = [];
		const issues: ParseIssue[] = [];
		let doc: unknown;
		try {
			doc = JSON.parse(text);
		} catch {
			return { users, issues: [{ row: 0, code: "INVALID_JSON", message: "not valid JSON" }] };
		}
		const list = Array.isArray(doc) ? doc : asRecord(doc)?.users;
		(Array.isArray(list) ? list : []).forEach((raw, i) => {
			const rec = asRecord(raw);
			const id = str(rec?.id) ?? str(rec?.username);
			const email = str(rec?.email)?.toLowerCase();
			if (!rec || !id || !email) {
				issues.push({ row: i + 1, code: "MISSING_FIELD", message: "id and email are required" });
				return;
			}
			const creds = Array.isArray(rec.credentials) ? rec.credentials : [];
			const pw = creds.map(asRecord).find((c) => c !== null && c.type === "password");
			const fed = Array.isArray(rec.federatedIdentities) ? rec.federatedIdentities : [];
			const name = [str(rec.firstName), str(rec.lastName)].filter(Boolean).join(" ");
			const user: ImportedUser = {
				externalId: id,
				email,
				emailVerified: truthy(rec.emailVerified),
				name: name === "" ? str(rec.username) : name,
				linkedAccounts: fed.flatMap((f) => {
					const x = asRecord(f);
					const provider = str(x?.identityProvider);
					const pid = str(x?.userId);
					return provider && pid ? [{ provider, providerAccountId: pid }] : [];
				}),
				metadata: { username: str(rec.username), attributes: asRecord(rec.attributes) ?? {} },
			};
			const hash = pw ? credentialHash(pw) : null;
			if (hash) user.passwordHash = hash;
			else if (pw)
				issues.push({
					row: i + 1,
					code: "UNSUPPORTED_CREDENTIAL",
					message: "password credential is not a supported pbkdf2 variant",
				});
			users.push(user);
		});
		return { users, issues };
	},
};
