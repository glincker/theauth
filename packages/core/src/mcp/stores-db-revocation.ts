import { and, eq, gte, inArray, lt, or, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { mcpRevocations } from "../db/schema.js";
import { isUniqueViolation } from "../db/unique-violation.js";
import { getEnvNumber } from "../runtime/env.js";
import type {
	McpRevocationEntry,
	McpRevocationHit,
	McpRevocationKind,
	McpRevocationQuery,
	McpRevocationStore,
} from "./revocation-types.js";
import { MCP_REVOCATION_DEFAULTS } from "./revocation-types.js";

const t = mcpRevocations;

/** Rows this close below the newest one are counted by the fingerprint, whatever the skew setting. */
const FINGERPRINT_MIN_WINDOW_MS = 60_000;

/** Default clock skew allowance between instances for watermark rows. Env THEAUTH_MCP_REVOCATION_SKEW_MS. */
export const DEFAULT_REVOCATION_SKEW_MS = 0;

export interface DbRevocationStoreOptions {
	/**
	 * Skew bound between the clock of the instance that wrote a `sub` or `client` watermark
	 * (`revoked_at_ms`, that instance's clock) and the clock of the instance that minted the token
	 * (`iat`). A token is dead when `iat * 1000 <= revoked_at_ms + skew`, so a revoker whose clock
	 * lags by up to `skewAllowanceMs` still kills tokens minted just before the revoke. The cost is
	 * that a token minted within `skewAllowanceMs` after a revoke is also refused (fails closed).
	 * Default 0 (instances are assumed NTP synced; raise it, for example to 2000, when they are not).
	 */
	skewAllowanceMs?: number;
}

/** Epoch seconds, rounded up so a row never expires before the thing it denies. */
function toSeconds(d: Date): number {
	return Math.ceil(d.getTime() / 1000);
}

/** Keeps the first occurrence of each id and drops empty strings. */
function uniq(ids: readonly string[]): string[] {
	return [...new Set(ids.filter((id) => id.length > 0))];
}

/**
 * The shared revocation list in `theauth_mcp_revocations` (migration 0007). Writes are single
 * statements, never wrapped in a transaction: a duplicate key on Postgres would otherwise abort
 * the whole transaction. Only ids are stored, never token values.
 */
export function createDbRevocationStore(
	db: Database,
	options: DbRevocationStoreOptions = {},
): McpRevocationStore {
	const rawSkew =
		options.skewAllowanceMs ??
		getEnvNumber("THEAUTH_MCP_REVOCATION_SKEW_MS") ??
		DEFAULT_REVOCATION_SKEW_MS;
	const skewMs =
		Number.isFinite(rawSkew) && rawSkew >= 0 ? Math.floor(rawSkew) : DEFAULT_REVOCATION_SKEW_MS;
	async function upsert(entry: McpRevocationEntry, revokedAtMs: number): Promise<void> {
		const expiresAt = toSeconds(entry.expiresAt);
		const sourceId = entry.sourceId ?? null;
		const raise = async (): Promise<void> => {
			// Watermarks and expiries only ever move forward, so a late re-revoke never weakens a row.
			await db
				.update(t)
				.set({
					revokedAtMs: sql`CASE WHEN ${t.revokedAtMs} < ${revokedAtMs} THEN ${revokedAtMs} ELSE ${t.revokedAtMs} END`,
					expiresAt: sql`CASE WHEN ${t.expiresAt} < ${expiresAt} THEN ${expiresAt} ELSE ${t.expiresAt} END`,
					reason: entry.reason,
					sourceId,
				})
				.where(and(eq(t.kind, entry.kind), eq(t.id, entry.id)));
		};
		try {
			await db.insert(t).values({
				kind: entry.kind,
				id: entry.id,
				revokedAtMs,
				expiresAt,
				reason: entry.reason,
				sourceId,
			});
		} catch (error) {
			if (!isUniqueViolation(error)) throw error;
			await raise();
		}
	}

	async function revokeMany(entries: McpRevocationEntry[], revokedAt?: Date): Promise<void> {
		const at = (revokedAt ?? new Date()).getTime();
		for (const entry of entries) {
			if (entry.id.length === 0) continue;
			await upsert(entry, at);
		}
	}

	return {
		revokeMany,

		async revoke(jti, expiresAt) {
			await revokeMany([{ kind: "jti", id: jti, expiresAt, reason: "token.revoke" }]);
		},

		async isRevoked(jti) {
			const rows = await db
				.select({ id: t.id })
				.from(t)
				.where(and(eq(t.kind, "jti"), eq(t.id, jti)))
				.limit(1);
			return rows.length > 0;
		},

		async check(q: McpRevocationQuery): Promise<McpRevocationHit | null> {
			const dlg = uniq(q.dlg);
			const agents = uniq(q.agents);
			const conditions = [
				and(eq(t.kind, "jti"), eq(t.id, q.jti)),
				and(eq(t.kind, "sub"), eq(t.id, q.sub)),
				and(eq(t.kind, "client"), eq(t.id, q.clientId)),
			];
			if (dlg.length > 0) conditions.push(and(eq(t.kind, "dlg"), inArray(t.id, dlg)));
			if (agents.length > 0) conditions.push(and(eq(t.kind, "agent"), inArray(t.id, agents)));
			const rows = await db
				.select({ kind: t.kind, id: t.id, revokedAtMs: t.revokedAtMs })
				.from(t)
				.where(or(...conditions))
				.limit(3 + dlg.length + agents.length);

			const iatMs = q.iat * 1000;
			const hits = new Map<McpRevocationKind, McpRevocationHit>();
			for (const row of rows) {
				if (hits.has(row.kind)) continue;
				// Watermarks: a token minted before the revoke, or within the skew allowance after it, is dead
				// (fail closed). revoked_at_ms is the pushing instance's clock, never ours.
				// Number() because BIGINT arrives as a string on some Postgres drivers.
				if (
					(row.kind === "sub" || row.kind === "client") &&
					!(iatMs <= Number(row.revokedAtMs) + skewMs)
				) {
					continue;
				}
				hits.set(row.kind, { kind: row.kind, id: row.id });
			}
			for (const kind of ["jti", "sub", "client", "dlg", "agent"] as const) {
				const hit = hits.get(kind);
				if (hit) return hit;
			}
			return null;
		},

		/**
		 * Cheap change marker, two index range reads instead of COUNT(*) over the whole table:
		 * the newest `revoked_at_ms` and the number of rows within the skew window below it. A row
		 * pushed by an instance whose clock lags by less than the window still changes the count;
		 * pruning old rows does not touch it.
		 */
		async fingerprint() {
			const [top] = await db
				.select({ m: sql<string | number | null>`max(${t.revokedAtMs})` })
				.from(t);
			const max = Number(top?.m ?? 0);
			if (max === 0) return "0:0";
			const [near] = await db
				.select({ n: sql<string | number>`count(*)` })
				.from(t)
				.where(gte(t.revokedAtMs, Math.max(0, max - Math.max(skewMs, FINGERPRINT_MIN_WINDOW_MS))));
			return `${Number(near?.n ?? 0)}:${max}`;
		},

		async prune(now, limit = MCP_REVOCATION_DEFAULTS.pruneLimit) {
			const cutoff = Math.floor(now.getTime() / 1000);
			const expired = await db
				.select({ kind: t.kind, id: t.id })
				.from(t)
				.where(lt(t.expiresAt, cutoff))
				.limit(Math.max(1, limit));
			if (expired.length === 0) return 0;
			await db
				.delete(t)
				.where(
					and(
						lt(t.expiresAt, cutoff),
						or(...expired.map((row) => and(eq(t.kind, row.kind), eq(t.id, row.id)))),
					),
				);
			return expired.length;
		},
	};
}
