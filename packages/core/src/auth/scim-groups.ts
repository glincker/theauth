import { and, eq, inArray, sql } from "drizzle-orm";
import { organizations, orgMembers, users } from "../db/schema.js";
import type { FilterAst } from "./scim-filter.js";
import { evaluateFilter, ScimFilterError } from "./scim-filter.js";
import type { FilterClause } from "./scim-helpers.js";
import {
	buildGroupSqlConditions,
	generateId,
	getBaseUrl,
	orgRowToScim,
	parseScimFilter,
	parseSortSpec,
	SCHEMA_LIST,
	SCHEMA_PATCH,
	scimError,
	scimResponse,
	sortResources,
} from "./scim-helpers.js";
import type { OrgMemberRow, OrgRow, PatchBody, ScimHandlerContext } from "./scim-types.js";

export function createScimGroupHandlers(ctx: ScimHandlerContext) {
	const { db, writeScimAudit } = ctx;

	async function getMembersForOrg(orgId: string): Promise<OrgMemberRow[]> {
		return (await db
			.select()
			.from(orgMembers)
			.where(eq(orgMembers.orgId, orgId))) as OrgMemberRow[];
	}

	async function getMemberEmails(memberRows: OrgMemberRow[]): Promise<Map<string, string>> {
		if (memberRows.length === 0) return new Map();
		const ids = memberRows.map((m) => m.userId);
		const emailRows = (await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(inArray(users.id, ids))) as { id: string; email: string }[];
		return new Map(emailRows.map((r) => [r.id, r.email]));
	}

	async function handleListGroups(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const filterParam = url.searchParams.get("filter") ?? "";
		const startIndex = Math.max(1, parseInt(url.searchParams.get("startIndex") ?? "1", 10));
		const count = Math.min(200, parseInt(url.searchParams.get("count") ?? "100", 10));
		const baseUrl = getBaseUrl(request);
		const sortSpec = parseSortSpec(url);

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

		const conditions = clauses ? buildGroupSqlConditions(clauses) : null;
		const whereClause = conditions && conditions.length > 0 ? and(...conditions) : undefined;

		if (conditions !== null && !sortSpec) {
			const countRows = await db
				.select({ count: sql<number>`count(*)`.mapWith(Number) })
				.from(organizations)
				.where(whereClause);
			const totalResults = Number(countRows[0]?.count ?? 0);

			const offset = startIndex - 1;
			const orgRows = (await db
				.select()
				.from(organizations)
				.where(whereClause)
				.limit(count)
				.offset(offset)) as OrgRow[];

			const resources = await Promise.all(
				orgRows.map(async (org) => {
					const members = await getMembersForOrg(org.id);
					const memberEmails = await getMemberEmails(members);
					return orgRowToScim(org, members, memberEmails, baseUrl);
				}),
			);

			return scimResponse({
				schemas: [SCHEMA_LIST],
				totalResults,
				startIndex,
				itemsPerPage: orgRows.length,
				Resources: resources,
			});
		}

		const allOrgs = (await db.select().from(organizations)) as OrgRow[];
		const resources = await Promise.all(
			allOrgs.map(async (org) => {
				const members = await getMembersForOrg(org.id);
				const memberEmails = await getMemberEmails(members);
				return { org, scim: orgRowToScim(org, members, memberEmails, baseUrl) };
			}),
		);
		const matched = ast
			? resources.filter(({ scim }) => evaluateFilter(ast as FilterAst, scim))
			: resources;
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
	async function handleGetGroup(request: Request, groupId: string): Promise<Response> {
		const baseUrl = getBaseUrl(request);
		const orgRows = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		const orgRow = orgRows[0];
		if (!orgRow) return scimError("Group not found", 404, "noTarget");

		const members = await getMembersForOrg(groupId);
		const memberEmails = await getMemberEmails(members);
		return scimResponse(orgRowToScim(orgRow, members, memberEmails, baseUrl));
	}

	async function handleCreateGroup(request: Request): Promise<Response> {
		const auditStart = performance.now();
		let body: Record<string, unknown>;
		try {
			body = (await request.json()) as Record<string, unknown>;
		} catch {
			return scimError("Invalid JSON body", 400, "invalidValue");
		}

		const displayName = body.displayName as string | undefined;
		if (!displayName) {
			return scimError("displayName is required", 400, "invalidValue");
		}

		const externalId = (body.externalId as string | undefined) ?? null;

		const slug = displayName
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-|-$/g, "")
			.slice(0, 50);

		const existingSlug = (await db
			.select({ id: organizations.id })
			.from(organizations)
			.where(eq(organizations.slug, slug))
			.limit(1)) as { id: string }[];

		const finalSlug = existingSlug.length > 0 ? `${slug}-${generateId().slice(0, 8)}` : slug;

		const id = `org_scim_${generateId()}`;
		const now = new Date();

		// ownerId is NOT NULL, so SCIM groups use the first user as owner.
		const membersRaw = body.members as Array<{ value: string }> | undefined;
		const ownerCandidateId = membersRaw?.[0]?.value;

		let ownerId: string;
		if (ownerCandidateId) {
			ownerId = ownerCandidateId;
		} else {
			const firstUser = (await db.select({ id: users.id }).from(users).limit(1)) as {
				id: string;
			}[];
			const firstUserRow = firstUser[0];
			if (!firstUserRow) {
				return scimError(
					"Cannot create group: no users exist to assign as owner",
					422,
					"invalidValue",
				);
			}
			ownerId = firstUserRow.id;
		}

		const metadata: Record<string, unknown> = { "scim:provisioned": true };
		if (externalId) metadata["scim:externalId"] = externalId;

		await db.insert(organizations).values({
			id,
			name: displayName,
			slug: finalSlug,
			ownerId,
			metadata,
			createdAt: now,
			updatedAt: now,
		});

		if (membersRaw && membersRaw.length > 0) {
			const memberInserts = membersRaw.map((m) => ({
				id: `om_scim_${generateId()}`,
				orgId: id,
				userId: m.value,
				role: "member",
				joinedAt: now,
			}));
			await db.insert(orgMembers).values(memberInserts);
		}

		const orgRows = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, id))
			.limit(1)) as OrgRow[];
		const createdMembers = await getMembersForOrg(id);
		const memberEmails = await getMemberEmails(createdMembers);
		const baseUrl = getBaseUrl(request);
		await writeScimAudit(
			"scim.group.create",
			`scim:groups:${id}`,
			ownerId,
			Math.round(performance.now() - auditStart),
		);
		return scimResponse(
			orgRowToScim(orgRows[0] as OrgRow, createdMembers, memberEmails, baseUrl),
			201,
		);
	}

	async function handleReplaceGroup(request: Request, groupId: string): Promise<Response> {
		const auditStart = performance.now();
		const orgRows = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		const existingOrg = orgRows[0];
		if (!existingOrg) return scimError("Group not found", 404, "noTarget");

		let body: Record<string, unknown>;
		try {
			body = (await request.json()) as Record<string, unknown>;
		} catch {
			return scimError("Invalid JSON body", 400, "invalidValue");
		}

		const displayName = (body.displayName as string | undefined) ?? existingOrg.name;
		const externalId = (body.externalId as string | undefined) ?? null;
		const membersRaw = body.members as Array<{ value: string }> | undefined;

		const existingMeta = existingOrg.metadata ?? {};
		const metadata: Record<string, unknown> = { ...existingMeta };
		if (externalId) metadata["scim:externalId"] = externalId;
		else metadata["scim:externalId"] = undefined;

		const now = new Date();
		await db
			.update(organizations)
			.set({ name: displayName, metadata, updatedAt: now })
			.where(eq(organizations.id, groupId));

		if (membersRaw !== undefined) {
			// Diff against the current members instead of deleting all and re-inserting. A member who stays is
			// never absent from the group, keeps the row id and the role it already had, and a concurrent
			// PUT cannot interleave into the union of two lists.
			const wanted = new Set(membersRaw.map((m) => m.value));
			const current = await db
				.select({ id: orgMembers.id, userId: orgMembers.userId })
				.from(orgMembers)
				.where(eq(orgMembers.orgId, groupId));
			const present = new Set(current.map((r) => r.userId));
			const staleIds = current.filter((r) => !wanted.has(r.userId)).map((r) => r.id);
			if (staleIds.length > 0) {
				await db.delete(orgMembers).where(inArray(orgMembers.id, staleIds));
			}
			const added = [...wanted].filter((userId) => !present.has(userId));
			if (added.length > 0) {
				await db.insert(orgMembers).values(
					added.map((userId) => ({
						id: `om_scim_${generateId()}`,
						orgId: groupId,
						userId,
						role: "member",
						joinedAt: now,
					})),
				);
			}
		}

		const updatedOrg = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		const members = await getMembersForOrg(groupId);
		const memberEmails = await getMemberEmails(members);
		const baseUrl = getBaseUrl(request);
		await writeScimAudit(
			"scim.group.replace",
			`scim:groups:${groupId}`,
			(updatedOrg[0] as OrgRow).ownerId,
			Math.round(performance.now() - auditStart),
		);
		return scimResponse(orgRowToScim(updatedOrg[0] as OrgRow, members, memberEmails, baseUrl));
	}

	async function handlePatchGroup(request: Request, groupId: string): Promise<Response> {
		const auditStart = performance.now();
		const orgRows = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		const current = orgRows[0];
		if (!current) return scimError("Group not found", 404, "noTarget");

		let body: PatchBody;
		try {
			body = (await request.json()) as PatchBody;
		} catch {
			return scimError("Invalid JSON body", 400, "invalidValue");
		}

		if (
			!body.schemas?.includes(SCHEMA_PATCH) ||
			!Array.isArray(body.Operations) ||
			body.Operations.length === 0
		) {
			return scimError("Invalid PATCH body: missing Operations", 400, "invalidValue");
		}

		let displayName = current.name;
		const updatedMeta: Record<string, unknown> = { ...(current.metadata ?? {}) };
		const now = new Date();

		for (const op of body.Operations) {
			const opLower = op.op?.toLowerCase() as "add" | "replace" | "remove" | undefined;
			if (!opLower) continue;
			const path = op.path?.toLowerCase();

			if (opLower === "replace" && path === "displayname") {
				displayName = typeof op.value === "string" ? op.value : displayName;
			} else if (opLower === "add" && (path === "members" || !path)) {
				const val = op.value as Record<string, unknown> | Array<{ value: string }> | undefined;
				if (Array.isArray(val)) {
					for (const m of val) {
						if (typeof m.value === "string") {
							const existing = (await db
								.select({ id: orgMembers.id })
								.from(orgMembers)
								.where(and(eq(orgMembers.orgId, groupId), eq(orgMembers.userId, m.value)))
								.limit(1)) as { id: string }[];
							if (existing.length === 0) {
								await db.insert(orgMembers).values({
									id: `om_scim_${generateId()}`,
									orgId: groupId,
									userId: m.value,
									role: "member",
									joinedAt: now,
								});
							}
						}
					}
				} else if (val && typeof val === "object" && "displayName" in val) {
					displayName = (val as Record<string, unknown>).displayName as string;
				}
			} else if (opLower === "remove" && path?.startsWith("members")) {
				// path could be "members" (remove all) or "members[value eq \"userId\"]"
				const matchId = op.path?.match(/members\[value\s+eq\s+"([^"]+)"\]/i);
				if (matchId) {
					const targetUserId = matchId[1];
					if (targetUserId) {
						await db
							.delete(orgMembers)
							.where(and(eq(orgMembers.orgId, groupId), eq(orgMembers.userId, targetUserId)));
					}
				} else if (path === "members") {
					const val = op.value as Array<{ value: string }> | undefined;
					if (Array.isArray(val)) {
						for (const m of val) {
							if (typeof m.value === "string") {
								await db
									.delete(orgMembers)
									.where(and(eq(orgMembers.orgId, groupId), eq(orgMembers.userId, m.value)));
							}
						}
					} else {
						await db.delete(orgMembers).where(eq(orgMembers.orgId, groupId));
					}
				}
			}
		}

		await db
			.update(organizations)
			.set({ name: displayName, metadata: updatedMeta, updatedAt: now })
			.where(eq(organizations.id, groupId));

		const updatedOrg = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		const members = await getMembersForOrg(groupId);
		const memberEmails = await getMemberEmails(members);
		const baseUrl = getBaseUrl(request);
		await writeScimAudit(
			"scim.group.update",
			`scim:groups:${groupId}`,
			(updatedOrg[0] as OrgRow).ownerId,
			Math.round(performance.now() - auditStart),
		);
		return scimResponse(orgRowToScim(updatedOrg[0] as OrgRow, members, memberEmails, baseUrl));
	}

	async function handleDeleteGroup(_request: Request, groupId: string): Promise<Response> {
		const auditStart = performance.now();
		const orgRows = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		const existing = orgRows[0];
		if (!existing) return scimError("Group not found", 404, "noTarget");

		await db.delete(orgMembers).where(eq(orgMembers.orgId, groupId));
		await db.delete(organizations).where(eq(organizations.id, groupId));

		await writeScimAudit(
			"scim.group.delete",
			`scim:groups:${groupId}`,
			existing.ownerId,
			Math.round(performance.now() - auditStart),
		);
		return new Response(null, { status: 204 });
	}

	return {
		handleListGroups,
		handleGetGroup,
		handleCreateGroup,
		handleReplaceGroup,
		handlePatchGroup,
		handleDeleteGroup,
	};
}
