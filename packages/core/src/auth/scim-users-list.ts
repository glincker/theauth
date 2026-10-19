import { and, sql } from "drizzle-orm";
import { users } from "../db/schema.js";
import type { FilterAst } from "./scim-filter.js";
import { evaluateFilter, ScimFilterError } from "./scim-filter.js";
import type { FilterClause } from "./scim-helpers.js";
import {
	buildUserSqlConditions,
	getBaseUrl,
	parseScimFilter,
	parseSortSpec,
	SCHEMA_LIST,
	scimError,
	scimResponse,
	sortResources,
	userRowToScim,
} from "./scim-helpers.js";
import type { ScimHandlerContext, UserRow } from "./scim-types.js";

/** GET /Users with filter, sort and paging (RFC 7644 3.4.2). */
export function createScimListHandler(ctx: ScimHandlerContext) {
	const { db } = ctx;

	async function handleListUsers(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const filterParam = url.searchParams.get("filter") ?? "";
		const startIndex = Math.max(1, parseInt(url.searchParams.get("startIndex") ?? "1", 10));
		const count = Math.min(200, parseInt(url.searchParams.get("count") ?? "100", 10));
		const baseUrl = getBaseUrl(request);
		const sortSpec = parseSortSpec(url);

		// Simple AND-of-clauses filters take the SQL fast path; complex ones fall back to in-memory evaluation.
		let ast: FilterAst | null = null;
		let clauses: FilterClause[] | null = null;
		if (filterParam) {
			try {
				const parsed = parseScimFilter(filterParam);
				ast = parsed.ast;
				clauses = parsed.clauses;
			} catch (err) {
				if (err instanceof ScimFilterError) {
					return scimError(err.message, 400, "invalidFilter");
				}
				throw err;
			}
		}

		const conditions = clauses ? buildUserSqlConditions(clauses) : null;
		const whereClause = conditions && conditions.length > 0 ? and(...conditions) : undefined;

		// Sorting needs the full filtered set before pagination, and SQL ORDER BY cannot reach JSON metadata.
		if (conditions !== null && !sortSpec) {
			const countRows = await db
				.select({ count: sql<number>`count(*)`.mapWith(Number) })
				.from(users)
				.where(whereClause);
			const totalResults = Number(countRows[0]?.count ?? 0);

			const offset = startIndex - 1;
			const rows = (await db
				.select()
				.from(users)
				.where(whereClause)
				.limit(count)
				.offset(offset)) as UserRow[];

			return scimResponse({
				schemas: [SCHEMA_LIST],
				totalResults,
				startIndex,
				itemsPerPage: rows.length,
				Resources: rows.map((r) => userRowToScim(r, baseUrl)),
			});
		}

		const allRows = (await db.select().from(users)) as UserRow[];
		const mapped = allRows.map((r) => ({ row: r, scim: userRowToScim(r, baseUrl) }));
		const matched = ast
			? mapped.filter(({ scim }) => evaluateFilter(ast as FilterAst, scim))
			: mapped;
		const sorted = sortSpec ? sortResources(matched, sortSpec) : matched;
		const totalResults = sorted.length;
		const page = sorted.slice(startIndex - 1, startIndex - 1 + count);

		return scimResponse({
			schemas: [SCHEMA_LIST],
			totalResults,
			startIndex,
			itemsPerPage: page.length,
			Resources: page.map((p) => p.scim),
		});
	}

	return handleListUsers;
}
