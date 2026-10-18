// Mint time resolution of the `theauth_dlg` delegation binding (design F1, section 5).
//
// A bound token names the agents its authority rests on (root first) and the delegation rows
// between them. Resolution reads live rows only, refuses anything that is missing, revoked or
// expired, and returns the earliest expiry on the path so the minted token never outlives it.

import type {
	McpBindingStore,
	McpDelegationBinding,
	McpMintBinding,
	McpMintBindingInput,
} from "./revocation-types.js";
import { MCP_DELEGATION_BINDING_VERSION, MCP_PARENT_JTI_MAX } from "./revocation-types.js";
import type { McpActorClaim, McpActorRef, McpAuthContext, Result } from "./types.js";

/** `validUntil` when nothing on the path expires (the latest Date JavaScript can hold). */
export const MCP_BINDING_NO_EXPIRY = new Date(8_640_000_000_000_000);

/** Maps an actor to the agent id used in delegation records. Never returns an empty id. */
export type McpBindingActorMapper = (actor: McpActorRef) => Promise<string>;

const STORES = new WeakMap<McpAuthContext, McpBindingStore>();

/** Attach the delegation binding store to a context. `createMcpModule` calls it once (database stores). */
export function attachBindingStore(ctx: McpAuthContext, store: McpBindingStore): void {
	STORES.set(ctx, store);
}

/** The binding store attached to a context, or undefined: tokens are then minted unbound, as before F1. */
export function bindingStoreOf(ctx: McpAuthContext): McpBindingStore | undefined {
	return STORES.get(ctx);
}

/** `config.revocation.requireBoundChain`, default false. */
export function requireBoundChain(ctx: McpAuthContext): boolean {
	return ctx.config.revocation?.requireBoundChain === true;
}

/**
 * Actor to agent mapping for binding: `config.resolveActorAgentId` first, then the built in rule
 * (the agent the actor's client is bound to, else the actor's own id). An empty mapping falls back
 * to the raw id, so an actor that is an agent row is never silently left out of the binding.
 * A mapper that throws propagates; callers refuse the mint.
 */
export function bindingActorMapper(ctx: McpAuthContext): McpBindingActorMapper {
	const custom = ctx.config.resolveActorAgentId;
	return async (actor) => {
		const mapped = custom ? await custom(actor) : undefined;
		if (mapped) return mapped;
		if (actor.clientId) {
			const client = await ctx.findClient(actor.clientId);
			if (client?.agentId) return client.agentId;
		}
		return actor.sub;
	};
}

/**
 * Shape check for a `theauth_dlg` value read from a token whose signature already verified.
 * Undefined when absent, null when present but malformed (never trusted partially).
 */
export function readBindingClaim(raw: unknown): McpDelegationBinding | null | undefined {
	if (raw === undefined) return undefined;
	if (typeof raw !== "object" || raw === null) return null;
	const { v, agt, lnk } = raw as Record<string, unknown>;
	if (v !== MCP_DELEGATION_BINDING_VERSION || !Array.isArray(agt) || !Array.isArray(lnk)) {
		return null;
	}
	const ok = (x: unknown): x is string => typeof x === "string" && x.length > 0 && x.length <= 256;
	if (agt.length < 1 || agt.length > 32 || lnk.length !== agt.length - 1) return null;
	if (!agt.every(ok) || !lnk.every(ok)) return null;
	return { v: MCP_DELEGATION_BINDING_VERSION, agt: [...agt], lnk: [...lnk] };
}

/**
 * Shape check for a `theauth_pjti` value read from a verified token: undefined when absent, null
 * when malformed (the token is then invalid), else the ancestor jtis root first.
 */
export function readParentJtis(raw: unknown): string[] | null | undefined {
	if (raw === undefined) return undefined;
	if (!Array.isArray(raw) || raw.length < 1 || raw.length > MCP_PARENT_JTI_MAX) return null;
	const ok = (x: unknown): x is string => typeof x === "string" && x.length > 0 && x.length <= 256;
	return raw.every(ok) ? [...raw] : null;
}

/** Exchange specific input on top of the contract's `McpMintBindingInput`. */
export interface McpExchangeBindingInput extends McpMintBindingInput {
	/** The subject token's `agent_id` (legacy tokens minted before bindings), placed right after `sub`. */
	subjectAgentId?: string;
}

/** Most upstream hops prepended to an agent's path. The root's own upstream is still checked live by `check`. */
export const MCP_BINDING_MAX_UPSTREAM = 8;

/** Longest `agt` a token may carry (validators refuse longer). */
const MAX_AGT = 32;

/** `error.details.notEntitled` on a refusal: the agent the subject is not entitled to. */
export const MCP_BINDING_NOT_ENTITLED = "notEntitled";

function refuse(message: string, details?: Record<string, unknown>): Result<never> {
	return {
		success: false,
		error: { code: "INVALID_GRANT", message, ...(details ? { details } : {}) },
	};
}

function unavailable(error: unknown): Result<never> {
	return {
		success: false,
		error: {
			code: "SERVER_ERROR",
			message: `Delegation binding could not be resolved: ${error instanceof Error ? error.message : "unknown error"}`,
		},
	};
}

/** Actors of an `act` claim, innermost (oldest) first. Bounded so a hostile nesting cannot loop. */
function actorsInnermostFirst(act: McpActorClaim | undefined): McpActorRef[] {
	const out: McpActorRef[] = [];
	let node = act;
	while (typeof node === "object" && node !== null && out.length < 64) {
		if (typeof node.sub === "string" && node.sub) {
			out.push({
				sub: node.sub,
				...(typeof node.client_id === "string" ? { clientId: node.client_id } : {}),
			});
		}
		node = node.act;
	}
	return out.reverse();
}

/** Re-check a binding live and turn the verdict into a mint result with its expiry cap. */
async function finish(
	store: McpBindingStore,
	binding: McpDelegationBinding,
	now: Date,
	label: string,
): Promise<Result<McpMintBinding>> {
	const verdict = await store.check(binding, now);
	if (!verdict.live) {
		return refuse(`${label} is no longer live (${verdict.reason}: ${verdict.id})`);
	}
	const capAt =
		verdict.validUntil.getTime() >= MCP_BINDING_NO_EXPIRY.getTime() ? null : verdict.validUntil;
	return { success: true, data: { binding, capAt } };
}

/**
 * The live inbound path above `agentId`, root first, excluding `agentId` itself: at each hop the
 * earliest created live inbound link. One path is named even when several exist; if that path dies
 * the token dies with it (fail closed) and the client mints again over a path that is still live.
 * Bounded by {@link MCP_BINDING_MAX_UPSTREAM} and `room`; stops at a loop.
 */
async function upstreamOf(
	store: McpBindingStore,
	agentId: string,
	now: Date,
	room: number,
	seen: Set<string>,
): Promise<{ agt: string[]; lnk: string[] }> {
	const agt: string[] = [];
	const lnk: string[] = [];
	if (!store.liveInbound) return { agt, lnk };
	let current = agentId;
	const visited = new Set(seen).add(agentId);
	while (agt.length < Math.min(MCP_BINDING_MAX_UPSTREAM, room)) {
		const first = (await store.liveInbound(current, now))[0];
		if (!first || visited.has(first.from)) break;
		agt.unshift(first.from);
		lnk.unshift(first.id);
		visited.add(first.from);
		current = first.from;
	}
	return { agt, lnk };
}

/** Prepend the live upstream path of `agt[0]`, so revoking a delegation above it is seen in every mode. */
async function withUpstream(
	store: McpBindingStore,
	agt: string[],
	lnk: string[],
	now: Date,
): Promise<{ agt: string[]; lnk: string[] }> {
	const root = agt[0];
	if (root === undefined) return { agt, lnk };
	const up = await upstreamOf(store, root, now, MAX_AGT - agt.length, new Set(agt));
	return { agt: [...up.agt, ...agt], lnk: [...up.lnk, ...lnk] };
}

/**
 * Entitlement of the token subject to the agents of an exchange child (review finding M5). Some
 * entry `agt[k]` must be the subject itself, the agent the subject maps to, or an agent the subject
 * user owns. Every entry after `k` is then reached over live delegation links (delegated to the
 * chain); entries before `k` are upstream lenders that delegated to the subject's agent. A chain
 * with no such entry belongs to someone else: refused, naming the acting (last) agent.
 */
async function entitlementFailure(
	store: McpBindingStore,
	agt: string[],
	subject: string,
	subjectAgent: string,
): Promise<string | null> {
	const rows = await store.agents(agt);
	const entitled = agt.some(
		(id) => id === subject || id === subjectAgent || rows.get(id)?.ownerId === subject,
	);
	return entitled ? null : (agt[agt.length - 1] as string);
}

/** Link `from` to `to` with a live delegation row, or refuse. */
async function link(
	store: McpBindingStore,
	from: string,
	to: string,
	now: Date,
): Promise<Result<string>> {
	const found = await store.findLiveLink(from, to, now);
	if (!found) return refuse(`No live delegation from ${from} to ${to}`);
	return { success: true, data: found.id };
}

/**
 * Resolve the binding of a token exchange child. Steps (design section 5):
 * 1. Parent: the subject token's verified `theauth_dlg`, re-checked live; else resolved from
 *    `[sub, agent_id, ...act innermost first]`, keeping the ids that are agent rows, with a live
 *    link required between every consecutive pair.
 * 2. Actor: the new actor, mapped the same way. An agent distinct from the last entry needs a live
 *    link from it, then is appended.
 * 3. No agent anywhere: unbound, unless `requireBoundChain`.
 * The whole binding is then checked live once more (agents active and unexpired, link rows match
 * the named pairs, root still backed upstream) and its earliest expiry becomes `capAt`.
 * A mapper that throws refuses the mint; a store error is `SERVER_ERROR` (fail closed).
 */
export async function resolveExchangeBinding(
	store: McpBindingStore,
	mapActor: McpBindingActorMapper,
	input: McpExchangeBindingInput,
): Promise<Result<McpMintBinding>> {
	const { now } = input;
	const map = async (actor: McpActorRef): Promise<Result<string>> => {
		try {
			const id = await mapActor(actor);
			return { success: true, data: id || actor.sub };
		} catch {
			return refuse(`Actor ${actor.sub} could not be mapped to an agent`);
		}
	};
	try {
		let agt: string[] = [];
		let lnk: string[] = [];

		if (input.parent) {
			const parentCheck = await store.check(input.parent, now);
			if (!parentCheck.live) {
				return refuse(
					`subject_token delegation is no longer live (${parentCheck.reason}: ${parentCheck.id})`,
				);
			}
			agt = [...input.parent.agt];
			lnk = [...input.parent.lnk];
		} else {
			const ids: string[] = [];
			const subjectId = await map({ sub: input.subject });
			if (!subjectId.success) return subjectId;
			ids.push(subjectId.data);
			if (input.subjectAgentId) ids.push(input.subjectAgentId);
			for (const actor of actorsInnermostFirst(input.act)) {
				const mapped = await map(actor);
				if (!mapped.success) return mapped;
				ids.push(mapped.data);
			}
			const rows = await store.agents(ids);
			for (const id of ids) {
				if (!rows.has(id) || agt[agt.length - 1] === id) continue;
				const last = agt[agt.length - 1];
				if (last !== undefined) {
					const found = await link(store, last, id, now);
					if (!found.success) return found;
					lnk.push(found.data);
				}
				agt.push(id);
			}
		}

		const actorId = await map(input.actor);
		if (!actorId.success) return actorId;
		const last = agt[agt.length - 1];
		if (actorId.data !== last && (await store.agents([actorId.data])).has(actorId.data)) {
			if (last !== undefined) {
				const found = await link(store, last, actorId.data, now);
				if (!found.success) return found;
				lnk.push(found.data);
			}
			agt.push(actorId.data);
		}

		if (agt.length === 0) {
			if (input.requireBoundChain) {
				return refuse("Token exchange requires a delegation chain bound to agents");
			}
			return { success: true, data: { capAt: null } };
		}
		const full = await withUpstream(store, agt, lnk, now);
		if (full.agt.length > MAX_AGT) return refuse("Delegation chain is too long to bind");
		const subjectAgent = await map({ sub: input.subject });
		if (!subjectAgent.success) return subjectAgent;
		const foreign = await entitlementFailure(store, full.agt, input.subject, subjectAgent.data);
		if (foreign !== null) {
			return refuse("Subject is not entitled to the agents of this delegation", {
				[MCP_BINDING_NOT_ENTITLED]: foreign,
				agt: full.agt,
			});
		}
		return await finish(
			store,
			{ v: MCP_DELEGATION_BINDING_VERSION, agt: full.agt, lnk: full.lnk },
			now,
			"Delegation",
		);
	} catch (error) {
		return unavailable(error);
	}
}

/**
 * Binding for an ordinary (non exchange) token whose principal is the agent `agentId`: the agent's
 * live inbound path up to its root, then the agent (`agt: [root, ..., agentId]`, one `lnk` per hop;
 * `agt: [agentId], lnk: []` for an agent nobody delegated to). Revoking a delegation above the agent
 * then denies the token through `lnk` in every mode. An id that is not an agent row stays unbound;
 * an agent that is revoked, expired or no longer backed upstream refuses the mint.
 */
export async function resolveAgentBinding(
	store: McpBindingStore,
	agentId: string,
	now: Date,
): Promise<Result<McpMintBinding>> {
	try {
		if (!(await store.agents([agentId])).has(agentId)) {
			return { success: true, data: { capAt: null } };
		}
		const path = await withUpstream(store, [agentId], [], now);
		return await finish(
			store,
			{ v: MCP_DELEGATION_BINDING_VERSION, agt: path.agt, lnk: path.lnk },
			now,
			`Agent ${agentId}`,
		);
	} catch (error) {
		return unavailable(error);
	}
}

/** Earliest of the given instants, ignoring null and undefined. Null when none is given. */
export function earliest(...dates: Array<Date | null | undefined>): Date | null {
	let out: Date | null = null;
	for (const d of dates) {
		if (d && (out === null || d.getTime() < out.getTime())) out = d;
	}
	return out;
}
