/**
 * Keyed pseudonyms for the personal ids on an audit row.
 *
 * Version 2 chain rows hash a pseudonym of userId, agentId, subjectId, actorId
 * and approverId instead of the raw ids, and store the pseudonyms on the row
 * (id_pseudonyms). Erasure can then blank the raw columns and the row hash
 * stays valid.
 *
 * Tradeoff: a pseudonym is linkable by whoever holds the key, so it is
 * pseudonymization, not anonymization. Destroying the key would be an
 * additional erasure option. That is deliberately not implemented here (no key
 * shredding): the key is `audit.hmacKey` when configured, otherwise a random
 * per-installation secret kept in theauth_audit_secrets.
 */

import { eq } from "drizzle-orm";
import { hmacSha256, randomBytesHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditSecrets } from "../db/schema.js";

/** Prefix of the placeholders GDPR anonymization writes into NOT NULL id columns. */
export const ERASED_ID_PREFIX = "[deleted-";

const SECRET_ID = "audit-pseudonym-v1";
const secretCache = new WeakMap<object, string>();

export const PSEUDONYM_FIELDS = [
	"userId",
	"agentId",
	"subjectId",
	"actorId",
	"approverId",
] as const;
export type PseudonymField = (typeof PSEUDONYM_FIELDS)[number];
export type IdPseudonyms = Partial<Record<PseudonymField, string>>;

export interface PseudonymSource {
	userId?: string | null;
	agentId?: string | null;
	subjectId?: string | null;
	actorId?: string | null;
	approverId?: string | null;
}

export function isErasedId(value: string | null | undefined): boolean {
	return typeof value === "string" && value.startsWith(ERASED_ID_PREFIX);
}

async function readSecret(db: Database): Promise<string | undefined> {
	const cached = secretCache.get(db);
	if (cached) return cached;
	const rows = await db
		.select({ secret: auditSecrets.secret })
		.from(auditSecrets)
		.where(eq(auditSecrets.id, SECRET_ID))
		.limit(1);
	const secret = rows[0]?.secret;
	if (secret) secretCache.set(db, secret);
	return secret;
}

/**
 * The key pseudonyms are computed with. `hmacKey` wins. Otherwise the
 * per-installation secret, created on first use when `create` is set; a
 * read-only caller (the verifier) gets undefined if none exists yet.
 */
export async function resolvePseudonymKey(
	db: Database,
	hmacKey: string | undefined,
	create: boolean,
): Promise<string | undefined> {
	if (hmacKey) return hmacKey;
	const existing = await readSecret(db);
	if (existing || !create) return existing;
	try {
		await db.insert(auditSecrets).values({
			id: SECRET_ID,
			secret: randomBytesHex(32),
			createdAt: new Date(),
		});
	} catch {
		// Another writer created it first. Read theirs below.
	}
	const created = await readSecret(db);
	if (!created) throw new Error("could not create the audit pseudonym secret");
	return created;
}

export async function pseudonymize(key: string, id: string): Promise<string> {
	return hmacSha256(key, `theauth.audit.pseudonym.v1:${id}`);
}

export async function computePseudonyms(
	row: PseudonymSource,
	key: string,
): Promise<Record<string, string>> {
	const out: Record<string, string> = {};
	for (const field of PSEUDONYM_FIELDS) {
		const value = row[field];
		if (value) out[field] = await pseudonymize(key, value);
	}
	return out;
}

/**
 * Fields whose raw value is still present but does not match the stored
 * pseudonym, meaning the raw column was edited after the row was written.
 * Erased columns (null, or an anonymization placeholder) are skipped.
 */
export async function pseudonymMismatches(
	row: PseudonymSource & { idPseudonyms?: Record<string, string> | null },
	key: string,
): Promise<PseudonymField[]> {
	const stored = row.idPseudonyms ?? {};
	const bad: PseudonymField[] = [];
	for (const field of PSEUDONYM_FIELDS) {
		const raw = row[field];
		if (!raw || isErasedId(raw)) continue;
		if ((await pseudonymize(key, raw)) !== stored[field]) bad.push(field);
	}
	return bad;
}
