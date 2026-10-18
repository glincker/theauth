import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { delegationChains } from "../db/schema.js";
import { createDelegatorLiveness } from "../delegation/liveness.js";
import type {
	McpActorAgentResolver,
	McpActorRef,
	McpDelegationHop,
	McpDelegationLink,
	McpDelegationStore,
} from "./types.js";

/** Why a delegation chain failed the live check. */
export interface McpDelegationFailure {
	from: string;
	to: string;
	reason: "missing" | "revoked" | "expired" | "unmapped actor" | "mapper failed";
}

/** Options for {@link checkLiveDelegation}. */
export interface McpDelegationCheckOptions {
	/** Map each chain actor (and the subject) to an agent id before the link lookup. */
	resolveActorAgentId?: McpActorAgentResolver;
	/** Keep the raw id for actors the mapper returns `undefined` for, instead of failing. */
	allowUnmappedActors?: boolean;
	/** Clock override for tests. */
	now?: Date;
}

/**
 * Walk the delegation chain from a token against live link records.
 * The authority path runs from the token subject through the innermost actor out to the current actor, so each consecutive pair must have an active, unexpired link. Returns the first failing link, or null when every link is live (or there are no hops). An actor mapped to `undefined` fails with "unmapped actor" unless `allowUnmappedActors` is set, and a mapper that throws fails with "mapper failed". Failures report the raw ids from the token.
 */
export async function checkLiveDelegation(
	store: McpDelegationStore,
	subject: string,
	hops: McpDelegationHop[],
	options: McpDelegationCheckOptions = {},
): Promise<McpDelegationFailure | null> {
	const now = options.now ?? new Date();
	const actors: McpActorRef[] = [{ sub: subject }, ...[...hops].reverse()];
	const mapper = options.resolveActorAgentId;
	const ids: string[] = [];
	for (const actor of actors) {
		if (!mapper) {
			ids.push(actor.sub);
			continue;
		}
		let mapped: string | undefined;
		try {
			mapped = await mapper(actor);
		} catch {
			return failure(actors, ids.length, "mapper failed");
		}
		if (mapped === undefined || mapped === "") {
			if (!options.allowUnmappedActors) return failure(actors, ids.length, "unmapped actor");
			mapped = actor.sub;
		}
		ids.push(mapped);
	}
	for (let i = 0; i < ids.length - 1; i++) {
		const link = await store.findLink(ids[i] as string, ids[i + 1] as string);
		if (!link) return failure(actors, i + 1, "missing");
		if (link.status === "revoked") return failure(actors, i + 1, "revoked");
		if (link.status === "expired" || link.expiresAt <= now) {
			return failure(actors, i + 1, "expired");
		}
	}
	return null;
}

/** Build a failure for the link ending at `actors[toIndex]`, using raw token ids. */
function failure(
	actors: McpActorRef[],
	toIndex: number,
	reason: McpDelegationFailure["reason"],
): McpDelegationFailure {
	const to = actors[toIndex] as McpActorRef;
	const from = actors[Math.max(toIndex - 1, 0)] as McpActorRef;
	return { from: from.sub, to: to.sub, reason };
}

/**
 * Delegation store backed by the `delegation_chains` table, where the chain source and target ids are the `act` subjects (agent ids). When several rows link the same pair, a live one wins so a newer grant is not masked by an old revoked row. A live link whose delegator agent is revoked, expired or no longer backed by a live ancestor reports as revoked or expired.
 */
export function createDbDelegationStore(db: Database): McpDelegationStore {
	return {
		async findLink(from, to): Promise<McpDelegationLink | null> {
			const rows = await db
				.select()
				.from(delegationChains)
				.where(and(eq(delegationChains.fromAgentId, from), eq(delegationChains.toAgentId, to)));
			const now = new Date();
			const live = rows.find((r) => r.status === "active" && r.expiresAt > now);
			const row = live ?? rows[0];
			if (!row) return null;
			// A live link from a delegator that is itself revoked or expired lends nothing.
			if (live) {
				const state = await createDelegatorLiveness(db, now).delegatorState(from);
				if (state !== "live") return { status: state, expiresAt: row.expiresAt };
			}
			return { status: row.status, expiresAt: row.expiresAt };
		},
	};
}
