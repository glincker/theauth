/**
 * Rotating pseudonyms. The stable pseudonym in pseudonym.ts is linkable by whoever holds the key, across all time. With rotation, each period (a whole number of days since the epoch) gets its own random secret stored in theauth_audit_secrets, and a subject's pseudonym is keyed by that period secret. Pseudonyms of one subject differ between periods. When an old period secret is deleted (shredded), no key remains that can link that period to any other, even for the operator. The chain hash covers the stored pseudonyms, not the secrets, so shredding keeps the chain verifiable. The cost: raw ids still present in a shredded period can no longer be checked against their pseudonym.
 * The period secret is independent of `audit.hmacKey` on purpose: deriving it from that key would let the key holder recompute every period.
 */

import { eq, inArray, like } from "drizzle-orm";
import { hmacSha256, randomBytesHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditSecrets } from "../db/schema.js";
import type { PseudonymField, PseudonymSource } from "./pseudonym.js";
import { PSEUDONYM_FIELDS } from "./pseudonym.js";

export interface PseudonymRotation {
	/** Length of one period in days. Whole number, at least 1. */
	periodDays: number;
	/** Older periods whose secret is kept besides the current one. Default 1. Older secrets are shredded the first time a new period starts. */
	retainPeriods?: number;
}

/** Key of the period number inside `idPseudonyms`. Rows without it use the stable pseudonym. */
export const PERIOD_KEY = "period";

const SECRET_PREFIX = "audit-pseudonym-v1:p";
const DAY_MS = 24 * 60 * 60 * 1000;
const periodCache = new WeakMap<object, Map<number, string>>();

function cacheOf(db: Database): Map<number, string> {
	let m = periodCache.get(db);
	if (!m) {
		m = new Map();
		periodCache.set(db, m);
	}
	return m;
}

export function normalizeRotation(rotation: PseudonymRotation): Required<PseudonymRotation> {
	const periodDays = Math.floor(rotation.periodDays);
	if (!Number.isFinite(periodDays) || periodDays < 1) {
		throw new TypeError("audit.pseudonymRotation.periodDays must be a whole number of at least 1");
	}
	const retain = Math.floor(rotation.retainPeriods ?? 1);
	return { periodDays, retainPeriods: Number.isFinite(retain) && retain >= 0 ? retain : 1 };
}

export function periodOf(at: Date, periodDays: number): number {
	return Math.floor(at.getTime() / (periodDays * DAY_MS));
}

async function readPeriodSecret(db: Database, period: number): Promise<string | undefined> {
	const cache = cacheOf(db);
	const cached = cache.get(period);
	if (cached) return cached;
	const rows = await db
		.select({ secret: auditSecrets.secret })
		.from(auditSecrets)
		.where(eq(auditSecrets.id, `${SECRET_PREFIX}${period}`))
		.limit(1);
	const secret = rows[0]?.secret;
	if (secret) cache.set(period, secret);
	return secret;
}

/** Secret of a period, created on first use when `create` is set. A reader gets undefined for a shredded or unknown period. */
export async function resolvePeriodSecret(
	db: Database,
	period: number,
	create: boolean,
): Promise<string | undefined> {
	const existing = await readPeriodSecret(db, period);
	if (existing || !create) return existing;
	try {
		await db.insert(auditSecrets).values({
			id: `${SECRET_PREFIX}${period}`,
			secret: randomBytesHex(32),
			createdAt: new Date(),
		});
	} catch {
		// Another writer created it first. Read theirs below.
	}
	const created = await readPeriodSecret(db, period);
	if (!created) throw new Error("could not create the audit pseudonym period secret");
	return created;
}

export async function rotatingPseudonym(
	secret: string,
	period: number,
	id: string,
): Promise<string> {
	return hmacSha256(secret, `theauth.audit.pseudonym.v1:p${period}:${id}`);
}

/** Pseudonyms of a row under the secret of its period, plus the period number so the verifier knows which secret to use. */
export async function computeRotatingPseudonyms(
	row: PseudonymSource,
	secret: string,
	period: number,
): Promise<Record<string, string>> {
	const out: Record<string, string> = { [PERIOD_KEY]: String(period) };
	for (const field of PSEUDONYM_FIELDS) {
		const value = row[field];
		if (value) out[field] = await rotatingPseudonym(secret, period, value);
	}
	return out;
}

/** The period a stored pseudonym map was written under, or undefined for the stable scheme. */
export function storedPeriod(
	pseudonyms: Record<string, string> | null | undefined,
): number | undefined {
	const raw = pseudonyms?.[PERIOD_KEY];
	if (raw === undefined || !/^-?\d+$/.test(raw)) return undefined;
	return Number(raw);
}

/** Fields whose raw value still present does not match its rotating pseudonym. */
export async function rotatingMismatches(
	row: PseudonymSource & { idPseudonyms?: Record<string, string> | null },
	secret: string,
	period: number,
	isErased: (v: string) => boolean,
): Promise<PseudonymField[]> {
	const stored = row.idPseudonyms ?? {};
	const bad: PseudonymField[] = [];
	for (const field of PSEUDONYM_FIELDS) {
		const raw = row[field];
		if (!raw || isErased(raw)) continue;
		if ((await rotatingPseudonym(secret, period, raw)) !== stored[field]) bad.push(field);
	}
	return bad;
}

/**
 * Delete the secrets of periods older than `current - retainPeriods`. Returns the periods shredded. After this nobody can recompute the pseudonyms of those periods, so subjects cannot be linked across them.
 */
export async function shredPseudonymPeriods(
	db: Database,
	current: number,
	retainPeriods: number,
): Promise<number[]> {
	const rows = await db
		.select({ id: auditSecrets.id })
		.from(auditSecrets)
		.where(like(auditSecrets.id, `${SECRET_PREFIX}%`));
	const cutoff = current - retainPeriods;
	const stale: { id: string; period: number }[] = [];
	for (const { id } of rows) {
		const period = Number(id.slice(SECRET_PREFIX.length));
		if (Number.isInteger(period) && period < cutoff) stale.push({ id, period });
	}
	if (stale.length === 0) return [];
	await db.delete(auditSecrets).where(
		inArray(
			auditSecrets.id,
			stale.map((s) => s.id),
		),
	);
	const cache = cacheOf(db);
	for (const s of stale) cache.delete(s.period);
	return stale.map((s) => s.period).sort((a, b) => a - b);
}

async function newestPeriod(db: Database): Promise<number | undefined> {
	const rows = await db
		.select({ id: auditSecrets.id })
		.from(auditSecrets)
		.where(like(auditSecrets.id, `${SECRET_PREFIX}%`));
	let newest: number | undefined;
	for (const { id } of rows) {
		const period = Number(id.slice(SECRET_PREFIX.length));
		if (Number.isInteger(period) && (newest === undefined || period > newest)) newest = period;
	}
	return newest;
}

const lastSwept = new WeakMap<object, number>();

/** Pseudonyms for a row about to be written under rotation. The first write of a new period also shreds the secrets that fell out of the retention window. */
export async function pseudonymsForWrite(
	db: Database,
	row: PseudonymSource & { timestamp: Date },
	rotation: PseudonymRotation,
): Promise<Record<string, string>> {
	const { periodDays, retainPeriods } = normalizeRotation(rotation);
	let period = periodOf(row.timestamp, periodDays);
	if (!(await resolvePeriodSecret(db, period, false))) {
		// A backdated row (clock skew, import) for a period that fell out of the window must not bring
		// its secret back. It is keyed under the newest period instead, which the row records.
		const newest = await newestPeriod(db);
		if (newest !== undefined && period < newest - retainPeriods) period = newest;
	}
	const secret = await resolvePeriodSecret(db, period, true);
	if (!secret) throw new Error("no audit pseudonym period secret available");
	if (lastSwept.get(db) !== period) {
		lastSwept.set(db, period);
		await shredPseudonymPeriods(db, period, retainPeriods);
	}
	return computeRotatingPseudonyms(row, secret, period);
}
