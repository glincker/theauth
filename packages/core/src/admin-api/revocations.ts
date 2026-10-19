import { desc, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { delegationChains, mcpRevocations } from "../db/schema.js";
import type { RevocationBus, RevocationBusStats } from "../mcp/revocation-bus.js";
import { revocationRowExpiry } from "../mcp/revocation-bus.js";
import type { McpRevocationKind } from "../mcp/revocation-types.js";
import { json } from "../plugin/helpers.js";
import type { EndpointContext, PluginEndpoint } from "../plugin/types.js";
import { asEnum, asId, asLimit, asReason, isRecord } from "./validate.js";

const KINDS = ["jti", "dlg", "agent", "sub", "client"] as const;
const MAX_ROWS = 500;
const MAX_LINKS = 200;

export interface RevocationRowView {
	kind: McpRevocationKind;
	id: string;
	revokedAt: string;
	expiresAt: string;
	reason: string;
	sourceId: string | null;
}

export interface DelegationImpactView {
	id: string;
	fromAgentId: string;
	toAgentId: string;
	expiresAt: string;
	/** Link ids a revoke of this link would deny: this one plus every active downstream link. */
	cascade: string[];
	/** Agents that lose delegated authority through this revoke. */
	agents: string[];
	/** A `dlg` row already exists for this link. */
	denied: boolean;
	/** MCP tokens are stateless JWTs, so impact is a rule: any token whose theauth_dlg.lnk holds one of `cascade`. */
	tokenRule: string;
}

export interface RevocationsView {
	rows: RevocationRowView[];
	/** Counters of this instance's bus, null when the instance has no bus. */
	stats: RevocationBusStats | null;
}

type Principal = { id: string };
type Handler = (p: Principal, req: Request, ctx: EndpointContext) => Promise<Response>;

export interface RevocationRouteDeps {
	db: Database;
	revocations?: RevocationBus;
	add: (method: PluginEndpoint["method"], path: string, description: string, h: Handler) => void;
	audit: (
		p: Principal,
		action: string,
		resource: string,
		result: "allowed" | "denied",
		parameters: Record<string, unknown>,
	) => Promise<boolean>;
	revokeDelegation: (id: string, options: { revokedBy?: string }) => Promise<string[]>;
	fail: (status: number, code: string, message: string) => Response;
}

/** Live denylist rows, newest first. Ids and reasons only, never token values. */
export async function listRevocationRows(
	db: Database,
	max: number,
	kind?: McpRevocationKind,
): Promise<RevocationRowView[]> {
	const base = db.select().from(mcpRevocations);
	const rows = await (kind ? base.where(eq(mcpRevocations.kind, kind)) : base)
		.orderBy(desc(mcpRevocations.revokedAtMs))
		.limit(max);
	return rows.map((r) => ({
		kind: r.kind,
		id: r.id,
		revokedAt: new Date(Number(r.revokedAtMs)).toISOString(),
		expiresAt: new Date(Number(r.expiresAt) * 1000).toISOString(),
		reason: r.reason,
		sourceId: r.sourceId,
	}));
}

/** Active delegation links with the cascade a revoke would cause, mirroring the cascade in `revokeDelegation`. */
export async function delegationImpact(db: Database): Promise<DelegationImpactView[]> {
	const active = await db
		.select()
		.from(delegationChains)
		.where(eq(delegationChains.status, "active"))
		.orderBy(desc(delegationChains.createdAt))
		.limit(MAX_ROWS);
	const live = active.filter((r) => r.expiresAt.getTime() > Date.now());
	const roots = live.slice(0, MAX_LINKS);
	const denied = new Set(
		(await db.select().from(mcpRevocations).where(eq(mcpRevocations.kind, "dlg"))).map((r) => r.id),
	);
	const byFrom = new Map<string, typeof live>();
	for (const row of live) {
		const siblings = byFrom.get(row.fromAgentId);
		if (siblings) siblings.push(row);
		else byFrom.set(row.fromAgentId, [row]);
	}

	return roots.map((root) => {
		const cascade: string[] = [];
		const agents = new Set<string>();
		const seen = new Set<string>();
		const walk = (row: (typeof live)[number]): void => {
			if (seen.has(row.id)) return;
			seen.add(row.id);
			cascade.push(row.id);
			agents.add(row.toAgentId);
			for (const child of byFrom.get(row.toAgentId) ?? []) walk(child);
		};
		walk(root);
		return {
			id: root.id,
			fromAgentId: root.fromAgentId,
			toAgentId: root.toAgentId,
			expiresAt: root.expiresAt.toISOString(),
			cascade,
			agents: [...agents],
			denied: denied.has(root.id),
			tokenRule: "tokens whose theauth_dlg.lnk holds any id in cascade",
		};
	});
}

/** Registers GET /revocations, GET /revocations/delegations and POST /revocations on the admin API. */
export function registerRevocationRoutes(deps: RevocationRouteDeps): void {
	const { db, revocations, add, audit, fail } = deps;

	add(
		"GET",
		"/revocations",
		"List the MCP revocation denylist and bus stats (admin only)",
		async (_p, req) => {
			const url = new URL(req.url);
			const kindRaw = url.searchParams.get("kind");
			const kind = kindRaw === null ? undefined : asEnum(kindRaw, KINDS);
			if (kindRaw !== null && !kind) return fail(400, "INVALID_QUERY", "kind is invalid");
			const max = asLimit(url.searchParams.get("limit"), 100, MAX_ROWS);
			const view: RevocationsView = {
				rows: await listRevocationRows(db, max, kind),
				stats: revocations ? revocations.stats() : null,
			};
			return json(view);
		},
	);

	add(
		"GET",
		"/revocations/delegations",
		"List delegation links with revoke impact (admin only)",
		async () => json(await delegationImpact(db)),
	);

	add(
		"POST",
		"/revocations",
		"Revoke a delegation, agent, subject, client or token id (admin only)",
		async (p, req) => {
			let body: unknown;
			try {
				body = await req.json();
			} catch {
				body = undefined;
			}
			if (!isRecord(body)) return fail(400, "INVALID_BODY", "JSON object body required");
			const kind = asEnum(body.kind, KINDS);
			const id = asId(body.id);
			const reason = body.reason === undefined ? "admin.revoke" : asReason(body.reason);
			if (!kind || !id) return fail(400, "INVALID_BODY", "kind and id are required");
			if (!reason)
				return fail(400, "INVALID_BODY", "reason must be a string of at most 500 characters");
			const resource = `revocation:${kind}:${id}`;

			if (kind === "dlg") {
				const [row] = await db
					.select()
					.from(delegationChains)
					.where(eq(delegationChains.id, id))
					.limit(1);
				if (!row) return fail(404, "NOT_FOUND", "Delegation not found");
				const revoked = await deps.revokeDelegation(id, { revokedBy: p.id });
				await audit(p, "admin_api.revocation.create", resource, "allowed", {
					kind,
					revoked,
					reason,
				});
				return json({ revoked }, 201);
			}

			if (!revocations) {
				await audit(p, "admin_api.revocation.create", resource, "denied", {
					kind,
					reason: "no_bus",
				});
				return fail(503, "REVOCATION_UNAVAILABLE", "This instance has no revocation bus");
			}
			const now = new Date();
			let expiresAt: Date | null = null;
			if (typeof body.expiresAt === "string") {
				const parsed = new Date(body.expiresAt);
				if (Number.isNaN(parsed.getTime()))
					return fail(400, "INVALID_BODY", "expiresAt is invalid");
				expiresAt = parsed;
			}
			await revocations.publish({ kind, ids: [id], revokedAt: now, reason, sourceId: p.id }, [
				{ kind, id, expiresAt: revocationRowExpiry(expiresAt, now), reason, sourceId: p.id },
			]);
			await audit(p, "admin_api.revocation.create", resource, "allowed", { kind, reason });
			return json({ revoked: [id] }, 201);
		},
	);
}
