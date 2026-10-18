/**
 * `auth.audit.checkpoint()`: pin where each chain starts today. For every chain it appends a chained `audit.checkpoint` row carrying an HMAC signed anchor (first row seq, id and hash), so the verifier can tell a legitimate start from deleted oldest rows. It returns the anchors and the new heads for you to store outside the database and pass back as `anchors` and `expectedHeads`.
 */

import { and, asc, desc, eq, isNotNull } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import { CHECKPOINT_ACTION, getAuditChainConfig, insertAuditRow } from "./chain.js";
import { signAnchor } from "./integrity.js";
import { resolvePseudonymKey } from "./pseudonym.js";
import type { ChainAnchor, ChainHead } from "./verify.js";

export interface ChainCheckpointOptions {
	/** Only this agent's chain. Default: every chain. */
	agentId?: string;
}

export interface ChainCheckpointResult {
	/** The first row of each chain at the time of the call. */
	anchors: Required<ChainAnchor>[];
	/** Each chain's head after the anchor row was appended. */
	heads: ChainHead[];
}

async function edgeRow(db: Database, agentId: string, newest: boolean) {
	const rows = await db
		.select({
			id: auditLogs.id,
			seq: auditLogs.chainSeq,
			hash: auditLogs.hash,
			userId: auditLogs.userId,
		})
		.from(auditLogs)
		.where(and(eq(auditLogs.agentId, agentId), isNotNull(auditLogs.chainSeq)))
		.orderBy(newest ? desc(auditLogs.chainSeq) : asc(auditLogs.chainSeq))
		.limit(1);
	return rows[0];
}

/**
 * Anchors the chains as they are now. It does not check them first: run `verifyAuditChain` before, because whatever start a chain has at this moment becomes its accepted start.
 */
export async function checkpointChains(
	db: Database,
	opts: ChainCheckpointOptions = {},
): Promise<Result<ChainCheckpointResult>> {
	try {
		const config = getAuditChainConfig(db);
		if (!config) {
			return {
				success: false,
				error: { code: "AUDIT_CHAIN_DISABLED", message: "audit.tamperEvident is not enabled" },
			};
		}
		const key = await resolvePseudonymKey(db, config.hmacKey, true);
		if (!key) throw new Error("no audit key available to sign the anchor");
		const scope = opts.agentId
			? and(isNotNull(auditLogs.chainSeq), eq(auditLogs.agentId, opts.agentId))
			: isNotNull(auditLogs.chainSeq);
		const agentRows = await db
			.selectDistinct({ agentId: auditLogs.agentId })
			.from(auditLogs)
			.where(scope)
			.orderBy(asc(auditLogs.agentId));

		const anchors: Required<ChainAnchor>[] = [];
		const heads: ChainHead[] = [];
		for (const { agentId } of agentRows) {
			const first = await edgeRow(db, agentId, false);
			if (!first || first.seq === null || first.hash === null) continue;
			const mac = await signAnchor(key, {
				kind: "anchor",
				agentId,
				firstSeq: first.seq,
				firstId: first.id,
				firstHash: first.hash,
			});
			await insertAuditRow(db, {
				id: `chk_${generateId()}`,
				agentId,
				userId: first.userId,
				action: CHECKPOINT_ACTION,
				resource: `audit:${agentId}`,
				parameters: {
					kind: "anchor",
					firstSeq: first.seq,
					firstId: first.id,
					firstHash: first.hash,
					mac,
				},
				result: "allowed",
				reason: "anchor",
				durationMs: 0,
				timestamp: new Date(),
				event: CHECKPOINT_ACTION,
			});
			anchors.push({ agentId, seq: first.seq, id: first.id, hash: first.hash });
			const head = await edgeRow(db, agentId, true);
			if (head && head.seq !== null && head.hash !== null) {
				heads.push({ agentId, seq: head.seq, hash: head.hash });
			}
		}
		return { success: true, data: { anchors, heads } };
	} catch (error) {
		return {
			success: false,
			error: {
				code: "AUDIT_CHECKPOINT_FAILED",
				message: error instanceof Error ? error.message : "Unknown",
			},
		};
	}
}
