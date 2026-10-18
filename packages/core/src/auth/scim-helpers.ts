import { eq, like, sql } from "drizzle-orm";
import { organizations, users } from "../db/schema.js";
import type { FilterAst } from "./scim-filter.js";
import { parseFilter } from "./scim-filter.js";
import type { OrgMemberRow, OrgRow, UserRow } from "./scim-types.js";

export const SCIM_CONTENT_TYPE = "application/scim+json";

export const SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
export const SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
export const SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
export const SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";

export const SCHEMA_SP_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
export const SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
export const SCHEMA_ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

export function scimResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": SCIM_CONTENT_TYPE },
	});
}

export function scimError(detail: string, status: number, scimType?: string): Response {
	return scimResponse(
		{
			schemas: [SCHEMA_ERROR],
			detail,
			status,
			...(scimType ? { scimType } : {}),
		},
		status,
	);
}

export function generateId(): string {
	return crypto.randomUUID().replace(/-/g, "");
}

export function toIso(date: Date): string {
	return date.toISOString();
}

export function extractId(pathname: string, prefix: string): string | null {
	const segments = pathname.split("/").filter(Boolean);
	const idx = segments.indexOf(prefix);
	if (idx === -1 || idx + 1 >= segments.length) return null;
	const seg = segments[idx + 1];
	return seg !== undefined ? decodeURIComponent(seg) : null;
}

export function userRowToScim(row: UserRow, baseUrl: string): Record<string, unknown> {
	const primaryEmail = row.email;
	const meta = row.metadata ?? {};
	const active = meta["scim:active"] !== false && row.banned === 0;

	const enterprise = meta["scim:enterprise"];
	const schemas = [SCHEMA_USER];
	if (enterprise && typeof enterprise === "object" && Object.keys(enterprise).length > 0) {
		schemas.push("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
	}

	const body: Record<string, unknown> = {
		schemas,
		id: row.id,
		externalId: row.externalId ?? undefined,
		userName: row.username ?? row.email,
		name: {
			formatted: row.name ?? undefined,
			givenName: (meta["scim:givenName"] as string | undefined) ?? undefined,
			familyName: (meta["scim:familyName"] as string | undefined) ?? undefined,
		},
		displayName: row.name ?? undefined,
		emails: [{ value: primaryEmail, primary: true, type: "work" }],
		active,
		meta: {
			resourceType: "User",
			created: toIso(row.createdAt),
			lastModified: toIso(row.updatedAt),
			location: `${baseUrl}/scim/v2/Users/${row.id}`,
		},
	};

	if (enterprise && typeof enterprise === "object") {
		body["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] = enterprise;
	}

	return body;
}

export function orgRowToScim(
	row: OrgRow,
	members: OrgMemberRow[],
	memberEmails: Map<string, string>,
	baseUrl: string,
): Record<string, unknown> {
	const meta = row.metadata ?? {};

	return {
		schemas: [SCHEMA_GROUP],
		id: row.id,
		externalId: (meta["scim:externalId"] as string | undefined) ?? undefined,
		displayName: row.name,
		members: members.map((m) => ({
			value: m.userId,
			display: memberEmails.get(m.userId) ?? m.userId,
			$ref: `${baseUrl}/scim/v2/Users/${m.userId}`,
		})),
		meta: {
			resourceType: "Group",
			created: toIso(row.createdAt),
			lastModified: toIso(row.updatedAt),
			location: `${baseUrl}/scim/v2/Groups/${row.id}`,
		},
	};
}

// Filter parsing, RFC 7644 §3.4.2.2. The full grammar lives in scim-filter.ts; a legacy clause array keeps SQL translation simple.

export type LegacyFilterOp = "eq" | "co" | "sw" | "pr";

export interface FilterClause {
	attribute: string;
	op: LegacyFilterOp;
	value?: string;
}

/** Flattens an AST into a legacy `and` clause list, or null when the filter is richer than that. */
export function flattenToLegacyClauses(ast: FilterAst): FilterClause[] | null {
	const clauses: FilterClause[] = [];
	const stack: FilterAst[] = [ast];
	while (stack.length > 0) {
		const node = stack.pop() as FilterAst;
		if (node.kind === "and") {
			stack.push(node.right, node.left);
			continue;
		}
		if (node.kind === "pr") {
			clauses.push({ attribute: attrKey(node.attr.path), op: "pr" });
			continue;
		}
		if (node.kind === "cmp") {
			if (node.op !== "eq" && node.op !== "co" && node.op !== "sw") return null;
			if (typeof node.value !== "string" && typeof node.value !== "boolean") return null;
			clauses.push({
				attribute: attrKey(node.attr.path),
				op: node.op,
				value: typeof node.value === "boolean" ? String(node.value) : node.value,
			});
			continue;
		}
		return null;
	}
	return clauses;
}

export function attrKey(path: string[]): string {
	return path.join(".").toLowerCase();
}

/** Parses a SCIM filter via the RFC 7644 AST. `clauses` is null when the filter is too rich for SQL. */
export function parseScimFilter(filter: string): {
	ast: FilterAst;
	clauses: FilterClause[] | null;
} {
	const ast = parseFilter(filter);
	const clauses = flattenToLegacyClauses(ast);
	return { ast, clauses };
}

export function getBaseUrl(request: Request): string {
	const url = new URL(request.url);
	return `${url.protocol}//${url.host}`;
}

// Sort helper, RFC 7644 §3.4.2.3. Ascending by default; ties break on id.

export interface SortSpec {
	by: string[];
	order: "ascending" | "descending";
}

export function parseSortSpec(url: URL): SortSpec | null {
	const by = url.searchParams.get("sortBy");
	if (!by) return null;
	const order = url.searchParams.get("sortOrder")?.toLowerCase();
	return {
		by: by.split(".").filter((p) => p.length > 0),
		order: order === "descending" ? "descending" : "ascending",
	};
}

export function sortResources<T extends { scim: Record<string, unknown> }>(
	items: T[],
	spec: SortSpec,
): T[] {
	const direction = spec.order === "descending" ? -1 : 1;
	return [...items].sort((a, b) => {
		const av = readAttr(a.scim, spec.by);
		const bv = readAttr(b.scim, spec.by);
		const primary = compareSortValues(av, bv);
		if (primary !== 0) return primary * direction;
		const ida = (a.scim.id as string | undefined) ?? "";
		const idb = (b.scim.id as string | undefined) ?? "";
		return ida < idb ? -1 : ida > idb ? 1 : 0;
	});
}

export function readAttr(resource: Record<string, unknown>, path: string[]): unknown {
	let current: unknown = resource;
	for (const segment of path) {
		if (current === undefined || current === null) return undefined;
		if (typeof current !== "object") return undefined;
		current = (current as Record<string, unknown>)[segment];
	}
	return current;
}

export function compareSortValues(a: unknown, b: unknown): number {
	if (a === undefined && b === undefined) return 0;
	if (a === undefined) return 1; // sort undefined to the end
	if (b === undefined) return -1;
	if (typeof a === "string" && typeof b === "string") {
		return a.toLowerCase().localeCompare(b.toLowerCase());
	}
	if (typeof a === "number" && typeof b === "number") {
		return a - b;
	}
	if (typeof a === "boolean" && typeof b === "boolean") {
		return a === b ? 0 : a ? 1 : -1;
	}
	return String(a).localeCompare(String(b));
}

export function buildUserSqlConditions(list: FilterClause[]): ReturnType<typeof eq>[] | null {
	const conds: ReturnType<typeof eq>[] = [];
	for (const clause of list) {
		if (clause.attribute === "username" && clause.value !== undefined) {
			if (clause.op === "eq") {
				conds.push(sql`(${users.username} = ${clause.value} OR ${users.email} = ${clause.value})`);
			} else if (clause.op === "co") {
				conds.push(
					sql`(${users.username} LIKE ${`%${clause.value}%`} OR ${users.email} LIKE ${`%${clause.value}%`})`,
				);
			} else if (clause.op === "sw") {
				conds.push(
					sql`(${users.username} LIKE ${`${clause.value}%`} OR ${users.email} LIKE ${`${clause.value}%`})`,
				);
			} else {
				return null;
			}
			continue;
		}
		if (clause.attribute === "emails.value" && clause.value !== undefined) {
			if (clause.op === "eq") conds.push(eq(users.email, clause.value));
			else if (clause.op === "co") conds.push(like(users.email, `%${clause.value}%`));
			else if (clause.op === "sw") conds.push(like(users.email, `${clause.value}%`));
			else return null;
			continue;
		}
		if (clause.attribute === "externalid" && clause.value !== undefined) {
			if (clause.op === "eq") conds.push(eq(users.externalId, clause.value));
			else return null;
			continue;
		}
		if (clause.attribute === "active") {
			if (clause.op === "eq" && clause.value === "false") conds.push(eq(users.banned, 1));
			else if (clause.op === "eq" && clause.value === "true") conds.push(eq(users.banned, 0));
			else return null;
			continue;
		}
		return null;
	}
	return conds;
}

export function buildGroupSqlConditions(list: FilterClause[]): ReturnType<typeof eq>[] | null {
	const conds: ReturnType<typeof eq>[] = [];
	for (const clause of list) {
		if (clause.attribute !== "displayname" || clause.value === undefined) return null;
		if (clause.op === "eq") conds.push(eq(organizations.name, clause.value));
		else if (clause.op === "co") conds.push(like(organizations.name, `%${clause.value}%`));
		else if (clause.op === "sw") conds.push(like(organizations.name, `${clause.value}%`));
		else return null;
	}
	return conds;
}
