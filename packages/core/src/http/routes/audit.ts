import { INPUT_SOURCE_KINDS, isInputSourceKind } from "../../audit/provenance.js";
import { isInvalidAuditCursor } from "../../audit/query.js";
import type { AuditExportOptions, AuditFilter } from "../../types.js";
import { badRequest, failure, ok, scopeDenied, scopeUnavailable } from "../respond.js";
import type { HttpRoute, RouteContext } from "../types.js";
import { listAgents } from "./agents.js";

function parseDate(value: string | null): Date | undefined {
	if (!value) return undefined;
	const d = new Date(value);
	return Number.isNaN(d.getTime()) ? undefined : d;
}

/** `provenanceKind`, `provenanceHash` and `provenanceContent` narrow to rows that recorded a matching input. Undefined when none is given or a value is malformed (the caller gets a 400 from `invalidProvenance`). */
function parseProvenance(q: URLSearchParams): AuditFilter["provenance"] {
	const kind = q.get("provenanceKind");
	const hash = q.get("provenanceHash");
	const content = q.get("provenanceContent");
	if (!kind && !hash && !content) return undefined;
	return {
		...(kind && isInputSourceKind(kind) ? { kind } : {}),
		...(hash ? { hash } : {}),
		...(content ? { content } : {}),
	};
}

function invalidProvenance(q: URLSearchParams): string | undefined {
	const kind = q.get("provenanceKind");
	if (kind && !isInputSourceKind(kind)) {
		return `provenanceKind must be one of ${INPUT_SOURCE_KINDS.join(", ")}`;
	}
	const hash = q.get("provenanceHash");
	if (hash && !/^[0-9a-f]{64}$/.test(hash)) {
		return "provenanceHash must be 64 lowercase hex characters";
	}
	return undefined;
}

function buildAuditFilter(url: URL): AuditFilter {
	const q = url.searchParams;
	const filter: AuditFilter = {};
	const agentId = q.get("agentId");
	const userId = q.get("userId");
	const actions = q.get("actions");
	const result = q.get("result");
	const limit = q.get("limit");
	const offset = q.get("offset");
	const order = q.get("order");
	const cursor = q.get("cursor");
	const events = q.get("events");
	const resource = q.get("resource");
	const since = parseDate(q.get("since"));
	const until = parseDate(q.get("until"));

	if (agentId) filter.agentId = agentId;
	if (userId) filter.userId = userId;
	if (since) filter.since = since;
	if (until) filter.until = until;
	if (actions) filter.actions = actions.split(",").map((a) => a.trim());
	if (
		result === "allowed" ||
		result === "denied" ||
		result === "rate_limited" ||
		result === "escalated"
	) {
		filter.result = result;
	}
	if (order === "asc" || order === "desc") filter.order = order;
	if (cursor) filter.cursor = cursor;
	if (events) filter.events = events.split(",").map((e) => e.trim());
	if (resource) filter.resource = resource;
	const provenance = parseProvenance(q);
	if (provenance) filter.provenance = provenance;
	if (limit) {
		const n = Number.parseInt(limit, 10);
		if (!Number.isNaN(n) && n > 0) filter.limit = n;
	}
	if (offset) {
		const n = Number.parseInt(offset, 10);
		if (!Number.isNaN(n) && n >= 0) filter.offset = n;
	}
	return filter;
}

async function queryAudit(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const badProvenance = invalidProvenance(ctx.url.searchParams);
	if (badProvenance) return badRequest(badProvenance);
	const scoped = ctx.scope.scopeAuditFilter(buildAuditFilter(ctx.url));
	if (!scoped.ok) return scopeDenied(scoped.denial);
	// Without `paged` or `cursor` the body stays a bare array (newest first). With either, it is
	// `{ entries, nextCursor }` and `nextCursor` is passed back as `cursor` for the next page.
	const paged = ctx.url.searchParams.get("paged") === "true" || Boolean(scoped.value.cursor);
	try {
		if (paged) return ok(await ctx.auth.audit.page(scoped.value));
		return ok(await ctx.auth.audit.query(scoped.value));
	} catch (err) {
		if (isInvalidAuditCursor(err)) return badRequest("cursor is not a valid audit cursor");
		return failure(err, "Failed to query audit logs");
	}
}

async function exportAudit(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const format = ctx.url.searchParams.get("format") ?? "json";
	if (format !== "json" && format !== "csv") return badRequest('format must be "json" or "csv"');
	const options: AuditExportOptions = { format };
	const since = parseDate(ctx.url.searchParams.get("since"));
	const until = parseDate(ctx.url.searchParams.get("until"));
	if (since) options.since = since;
	if (until) options.until = until;
	// An explicit owner filter is checked against the caller, never silently dropped.
	const userId = ctx.url.searchParams.get("userId");
	if (userId) options.userId = userId;

	const scoped = ctx.scope.scopeAuditExport(options);
	if (!scoped.ok) return scopeDenied(scoped.denial);
	try {
		const exported = await ctx.auth.audit.export(scoped.value);
		return new Response(exported, {
			status: 200,
			headers: {
				"Content-Type": format === "csv" ? "text/csv" : "application/json",
				"Content-Disposition": `attachment; filename="audit-export.${format}"`,
			},
		});
	} catch (err) {
		return failure(err, "Failed to export audit logs");
	}
}

async function dashboardStats(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	// Default guard: aggregate only the caller's own agents and audit rows.
	const owner = ctx.scope.statsOwnerId();
	try {
		const [agents, recent] = await Promise.all([
			ctx.auth.agent.list(owner ? { userId: owner } : undefined),
			ctx.auth.audit.query({
				since: new Date(Date.now() - 24 * 60 * 60 * 1000),
				limit: 1000,
				...(owner ? { userId: owner } : {}),
			}),
		]);
		const count = (status: string): number => agents.filter((a) => a.status === status).length;
		return ok({
			agents: {
				total: agents.length,
				active: count("active"),
				revoked: count("revoked"),
				expired: count("expired"),
			},
			users: { total: new Set(agents.map((a) => a.ownerId)).size },
			audit: {
				last24h: recent.length,
				allowed: recent.filter((e) => e.result === "allowed").length,
				denied: recent.filter((e) => e.result === "denied").length,
				rateLimited: recent.filter((e) => e.result === "rate_limited").length,
			},
		});
	} catch (err) {
		return failure(err, "Failed to fetch dashboard stats");
	}
}

export const auditRoutes: HttpRoute[] = [
	{
		method: "GET",
		path: "/audit",
		auth: "admin",
		group: "management",
		summary: "Query audit entries",
		handle: queryAudit,
	},
	{
		method: "GET",
		path: "/audit/export",
		auth: "admin",
		group: "management",
		summary: "Export audit entries as JSON or CSV",
		handle: exportAudit,
	},
	{
		method: "GET",
		path: "/dashboard/stats",
		auth: "admin",
		group: "management",
		summary: "Dashboard aggregates",
		handle: dashboardStats,
	},
	{
		method: "GET",
		path: "/dashboard/agents",
		auth: "admin",
		group: "management",
		summary: "Dashboard agent list (same as GET /agents)",
		handle: listAgents,
	},
	{
		method: "GET",
		path: "/dashboard/audit",
		auth: "admin",
		group: "management",
		summary: "Dashboard audit list (same as GET /audit)",
		handle: queryAudit,
	},
];
