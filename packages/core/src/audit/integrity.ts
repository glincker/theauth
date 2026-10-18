/**
 * MACs for the audit bookkeeping records that the verifier trusts: erasure entries (rows erased on purpose) and chain anchors (where a chain is allowed to start). The key is the audit key, `audit.hmacKey` when configured, otherwise the per-installation secret (see pseudonym.ts). Each payload carries its own type tag, so a MAC made for one purpose never validates for another.
 */

import { constantTimeEqual, hmacSha256 } from "../crypto/web-crypto.js";
import { canonicalJson } from "./chain.js";

const ERASURE_TAG = "theauth.audit.erasure.v1:";
const ANCHOR_TAG = "theauth.audit.anchor.v1:";

/** `anonymized`: the row was kept with its ids replaced. `deleted`: the row was removed. */
export type ErasureKind = "anonymized" | "deleted";

export interface ErasureEntry {
	id: string;
	agentId: string;
	seq: number;
	/** Hash the row had when it was erased. */
	hash: string;
	prevHash: string | null;
	/** hash_version of the row when it was erased (NULL is stored as 1). */
	hashVersion: number;
	reason: ErasureKind;
	/** For anonymized version 1 rows: the row hash recomputed over the rewritten row, so a later edit is still tamper. */
	erasedHash: string | null;
	mac: string;
}

export type UnsignedErasureEntry = Omit<ErasureEntry, "mac">;

function erasurePayload(e: UnsignedErasureEntry): string {
	return `${ERASURE_TAG}${canonicalJson({
		id: e.id,
		agentId: e.agentId,
		seq: e.seq,
		hash: e.hash,
		prevHash: e.prevHash,
		hashVersion: e.hashVersion,
		reason: e.reason,
		erasedHash: e.erasedHash,
	})}`;
}

export async function signErasureEntry(
	key: string,
	entry: UnsignedErasureEntry,
): Promise<ErasureEntry> {
	return { ...entry, mac: await hmacSha256(key, erasurePayload(entry)) };
}

function macEqual(a: string, b: string): boolean {
	const enc = new TextEncoder();
	return constantTimeEqual(enc.encode(a), enc.encode(b));
}

export async function erasureEntryValid(key: string, entry: ErasureEntry): Promise<boolean> {
	return macEqual(await hmacSha256(key, erasurePayload(entry)), entry.mac);
}

/** Read one entry of an erasure record. Undefined when the shape is wrong, which the verifier treats as forged. */
export function parseErasureEntry(item: unknown): ErasureEntry | undefined {
	if (!item || typeof item !== "object") return undefined;
	const e = item as Record<string, unknown>;
	const str = (v: unknown) => typeof v === "string";
	const strOrNull = (v: unknown) => v === null || typeof v === "string";
	if (!str(e.id) || !str(e.agentId) || !str(e.hash) || !str(e.mac)) return undefined;
	if (typeof e.seq !== "number" || typeof e.hashVersion !== "number") return undefined;
	if (!strOrNull(e.prevHash) || !strOrNull(e.erasedHash)) return undefined;
	if (e.reason !== "anonymized" && e.reason !== "deleted") return undefined;
	return {
		id: e.id as string,
		agentId: e.agentId as string,
		seq: e.seq,
		hash: e.hash as string,
		prevHash: e.prevHash as string | null,
		hashVersion: e.hashVersion,
		reason: e.reason,
		erasedHash: e.erasedHash as string | null,
		mac: e.mac as string,
	};
}

/**
 * Fields an anchor MAC covers. `retention`: cleanup deleted the chain through `throughSeq`, whose hash was `lastHash`. `anchor`: `auth.audit.checkpoint()` pinned the row at `firstSeq` (id `firstId`, hash `firstHash`) as the chain's start.
 */
export type AnchorFields =
	| { kind: "retention"; agentId: string; throughSeq: number; lastHash: string }
	| { kind: "anchor"; agentId: string; firstSeq: number; firstId: string; firstHash: string };

export async function signAnchor(key: string, fields: AnchorFields): Promise<string> {
	return hmacSha256(key, `${ANCHOR_TAG}${canonicalJson(fields)}`);
}

export async function anchorMacValid(
	key: string,
	fields: AnchorFields,
	mac: unknown,
): Promise<boolean> {
	if (typeof mac !== "string") return false;
	return macEqual(await signAnchor(key, fields), mac);
}
