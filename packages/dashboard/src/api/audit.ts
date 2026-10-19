import type { AuditInputRef, AuditLogEntry, AuditLogFilters, AuditResult } from "./types.js";

/** One row of core `GET /audit` (a bare array unless `paged=true`). Dates arrive as ISO strings. */
export interface CoreAuditEntry {
	id: string;
	agentId: string;
	userId?: string;
	action: string;
	resource: string;
	parameters?: Record<string, unknown>;
	result: AuditResult;
	reason?: string;
	code?: string;
	event?: string | null;
	durationMs: number;
	inputs?: AuditInputRef[];
	timestamp: string;
}

/**
 * Query string for core `GET /audit`. The route reads `actions`, `since`, `until`, `agentId`,
 * `result`, `limit`, `offset` and `provenanceKind`. One extra row is requested so the page can
 * tell whether a next page exists, because the route does not return a total.
 */
export function auditQuery(filters: AuditLogFilters | undefined, pageSize: number): string {
	const params = new URLSearchParams();
	if (filters?.agentId) params.set("agentId", filters.agentId);
	if (filters?.action) params.set("actions", filters.action);
	if (filters?.result) params.set("result", filters.result);
	if (filters?.provenanceKind) params.set("provenanceKind", filters.provenanceKind);
	if (filters?.from) params.set("since", filters.from);
	if (filters?.to) params.set("until", filters.to);
	params.set("limit", String(pageSize + 1));
	params.set("offset", String(filters?.offset ?? 0));
	return `?${params.toString()}`;
}

/** Query string for core `GET /audit/export`: format, since, until. */
export function auditExportQuery(format: "json" | "csv", filters?: AuditLogFilters): string {
	const params = new URLSearchParams({ format });
	if (filters?.from) params.set("since", filters.from);
	if (filters?.to) params.set("until", filters.to);
	return `?${params.toString()}`;
}

/** Map a core row to the dashboard row. `names` resolves the agent name, falling back to the id. */
export function toAuditLogEntry(raw: CoreAuditEntry, names: Map<string, string>): AuditLogEntry {
	return {
		id: raw.id,
		timestamp: raw.timestamp,
		agentId: raw.agentId,
		agentName: names.get(raw.agentId) ?? raw.agentId,
		action: raw.action,
		resource: raw.resource,
		result: raw.result,
		durationMs: raw.durationMs,
		metadata: raw.parameters ?? {},
		...(raw.code !== undefined && { code: raw.code }),
		...(raw.event ? { event: raw.event } : {}),
		...(raw.inputs && raw.inputs.length > 0 && { inputs: raw.inputs }),
	};
}
