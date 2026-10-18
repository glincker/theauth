import { and, eq, or, sql } from "drizzle-orm";
import { sessions, users } from "../db/schema.js";
import type { FilterAst } from "./scim-filter.js";
import { evaluateFilter, ScimFilterError } from "./scim-filter.js";
import type { FilterClause } from "./scim-helpers.js";
import {
	buildUserSqlConditions,
	generateId,
	getBaseUrl,
	parseScimFilter,
	parseSortSpec,
	SCHEMA_ENTERPRISE,
	SCHEMA_LIST,
	SCHEMA_PATCH,
	scimError,
	scimResponse,
	sortResources,
	userRowToScim,
} from "./scim-helpers.js";
import { applyPatchOps, ScimPatchError } from "./scim-patch.js";
import type { PatchBody, ScimHandlerContext, ScimUser, UserRow } from "./scim-types.js";
import { revokeUserMcpAccess } from "./user-revocation.js";

export function createScimUserHandlers(ctx: ScimHandlerContext) {
	const { db, writeScimAudit, config, revocations } = ctx;
	const {
		autoCreateUsers = true,
		autoDeactivateUsers = true,
		onProvision,
		onDeprovision,
		resolveSelf,
	} = config;

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

	async function handleGetUser(request: Request, userId: string): Promise<Response> {
		const baseUrl = getBaseUrl(request);
		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const row = rows[0];
		if (!row) return scimError("User not found", 404, "noTarget");
		return scimResponse(userRowToScim(row, baseUrl));
	}

	async function handleCreateUser(request: Request): Promise<Response> {
		const auditStart = performance.now();
		if (!autoCreateUsers) {
			return scimError("User provisioning is disabled", 403);
		}

		let body: Record<string, unknown>;
		try {
			body = (await request.json()) as Record<string, unknown>;
		} catch {
			return scimError("Invalid JSON body", 400, "invalidValue");
		}

		const userName = body.userName as string | undefined;
		if (!userName) {
			return scimError("userName is required", 400, "invalidValue");
		}

		const emailsRaw = body.emails as Array<{ value: string; primary?: boolean }> | undefined;
		const primaryEmail =
			emailsRaw?.find((e) => e.primary)?.value ?? emailsRaw?.[0]?.value ?? userName;

		const nameRaw = body.name as
			| { givenName?: string; familyName?: string; formatted?: string }
			| undefined;
		const givenName = nameRaw?.givenName;
		const familyName = nameRaw?.familyName;
		const nameFromParts = [givenName, familyName].filter(Boolean).join(" ") || null;
		const displayName = (body.displayName as string | undefined) ?? nameFromParts;

		const externalId = (body.externalId as string | undefined) ?? null;
		const active = (body.active as boolean | undefined) ?? true;

		const existing = (await db
			.select()
			.from(users)
			.where(or(eq(users.email, primaryEmail), eq(users.username, userName)))
			.limit(1)) as UserRow[];

		if (existing.length > 0) {
			return scimError("User already exists", 409, "uniqueness");
		}

		const id = `u_scim_${generateId()}`;
		const now = new Date();

		const metadata: Record<string, unknown> = {
			"scim:active": active,
			"scim:provisioned": true,
		};
		if (givenName) metadata["scim:givenName"] = givenName;
		if (familyName) metadata["scim:familyName"] = familyName;

		const enterpriseExt = body[SCHEMA_ENTERPRISE];
		if (enterpriseExt && typeof enterpriseExt === "object") {
			metadata["scim:enterprise"] = enterpriseExt;
		}

		await db.insert(users).values({
			id,
			email: primaryEmail,
			name: displayName,
			username: userName !== primaryEmail ? userName : null,
			externalId,
			externalProvider: "scim",
			banned: active ? 0 : 1,
			metadata,
			createdAt: now,
			updatedAt: now,
		});

		const createdRows = (await db
			.select()
			.from(users)
			.where(eq(users.id, id))
			.limit(1)) as UserRow[];
		const created = createdRows[0] as UserRow;

		const scimUser: ScimUser = {
			id,
			userName,
			name: { givenName, familyName },
			emails: [{ value: primaryEmail, primary: true }],
			active,
			externalId: externalId ?? undefined,
		};

		if (onProvision) {
			await onProvision(scimUser);
		}

		const baseUrl = getBaseUrl(request);
		await writeScimAudit(
			"scim.user.create",
			`scim:users:${id}`,
			id,
			Math.round(performance.now() - auditStart),
		);
		return scimResponse(userRowToScim(created, baseUrl), 201);
	}

	async function handleReplaceUser(request: Request, userId: string): Promise<Response> {
		const auditStart = performance.now();
		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const existing = rows[0];
		if (!existing) return scimError("User not found", 404, "noTarget");

		let body: Record<string, unknown>;
		try {
			body = (await request.json()) as Record<string, unknown>;
		} catch {
			return scimError("Invalid JSON body", 400, "invalidValue");
		}

		const userName = (body.userName as string | undefined) ?? existing.username ?? existing.email;
		const emailsRaw = body.emails as Array<{ value: string; primary?: boolean }> | undefined;
		const primaryEmail =
			emailsRaw?.find((e) => e.primary)?.value ?? emailsRaw?.[0]?.value ?? existing.email;

		const nameRaw = body.name as
			| { givenName?: string; familyName?: string; formatted?: string }
			| undefined;
		const givenName = nameRaw?.givenName;
		const familyName = nameRaw?.familyName;
		const nameFromParts = [givenName, familyName].filter(Boolean).join(" ") || null;
		const displayName = (body.displayName as string | undefined) ?? nameFromParts ?? existing.name;

		const externalId = (body.externalId as string | undefined) ?? existing.externalId;
		const active = (body.active as boolean | undefined) ?? true;

		const existingMeta = existing.metadata ?? {};
		const metadata: Record<string, unknown> = {
			...existingMeta,
			"scim:active": active,
		};
		if (givenName !== undefined) metadata["scim:givenName"] = givenName;
		if (familyName !== undefined) metadata["scim:familyName"] = familyName;

		const enterpriseExt = body[SCHEMA_ENTERPRISE];
		if (enterpriseExt && typeof enterpriseExt === "object") {
			metadata["scim:enterprise"] = enterpriseExt;
		}

		const now = new Date();
		await db
			.update(users)
			.set({
				email: primaryEmail,
				name: displayName ?? null,
				username: userName !== primaryEmail ? userName : existing.username,
				externalId,
				banned: active ? 0 : 1,
				metadata,
				updatedAt: now,
			})
			.where(eq(users.id, userId));
		// A deactivated user must not keep a live session.
		if (!active) {
			await db.delete(sessions).where(eq(sessions.userId, userId));
			await revokeUserMcpAccess(db, revocations, userId, "scim.deactivate");
		}

		const updatedRows = (await db
			.select()
			.from(users)
			.where(eq(users.id, userId))
			.limit(1)) as UserRow[];
		const baseUrl = getBaseUrl(request);
		await writeScimAudit(
			"scim.user.replace",
			`scim:users:${userId}`,
			userId,
			Math.round(performance.now() - auditStart),
		);
		return scimResponse(userRowToScim(updatedRows[0] as UserRow, baseUrl));
	}

	async function handlePatchUser(request: Request, userId: string): Promise<Response> {
		const auditStart = performance.now();
		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const current = rows[0];
		if (!current) return scimError("User not found", 404, "noTarget");

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

		// Serialize the current row to SCIM form, apply the PATCH ops against
		// that representation, then map the mutated fields back to DB columns.
		// This routes through the RFC 7644 §3.5.2 path engine in scim-patch.ts
		// which handles value-filter selectors (emails[type eq "work"].value)
		// and enforces immutable-attribute protections.
		const baseUrlForPatch = getBaseUrl(request);
		const scimView = userRowToScim(current, baseUrlForPatch) as Record<string, unknown>;

		try {
			applyPatchOps(scimView, body.Operations as Parameters<typeof applyPatchOps>[1], {
				readonlyPaths: ["id", "externalid"],
			});
		} catch (err) {
			if (err instanceof ScimPatchError) {
				return scimError(err.message, err.status, err.scimType);
			}
			throw err;
		}

		const updatedMeta: Record<string, unknown> = { ...(current.metadata ?? {}) };
		let email = current.email;
		let name = current.name;
		let username = current.username;
		let banned = current.banned;
		const externalId = current.externalId;

		const scimUserName = scimView.userName;
		if (typeof scimUserName === "string") username = scimUserName;

		const scimDisplay = scimView.displayName;
		if (typeof scimDisplay === "string") name = scimDisplay;

		const scimName = scimView.name as { givenName?: unknown; familyName?: unknown } | undefined;
		if (scimName) {
			if (scimName.givenName !== undefined) updatedMeta["scim:givenName"] = scimName.givenName;
			if (scimName.familyName !== undefined) updatedMeta["scim:familyName"] = scimName.familyName;
		}

		const scimActive = scimView.active;
		if (typeof scimActive === "boolean") {
			updatedMeta["scim:active"] = scimActive;
			banned = scimActive ? 0 : autoDeactivateUsers ? 1 : 0;
		} else if (scimActive === undefined && scimView.active === undefined) {
			updatedMeta["scim:active"] = false;
			banned = autoDeactivateUsers ? 1 : 0;
		}

		const scimEmails = scimView.emails;
		if (Array.isArray(scimEmails)) {
			const primary =
				(scimEmails.find(
					(entry): entry is { value?: unknown; primary?: unknown } =>
						typeof entry === "object" &&
						entry !== null &&
						(entry as { primary?: unknown }).primary === true,
				)?.value as string | undefined) ??
				(scimEmails[0] as { value?: unknown } | undefined)?.value;
			if (typeof primary === "string" && primary.length > 0) {
				email = primary;
			}
		}

		const extKey = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
		const enterpriseExt = scimView[extKey];
		if (enterpriseExt && typeof enterpriseExt === "object") {
			updatedMeta["scim:enterprise"] = enterpriseExt;
		}

		const now = new Date();
		await db
			.update(users)
			.set({ email, name, username, banned, externalId, metadata: updatedMeta, updatedAt: now })
			.where(eq(users.id, userId));
		// SCIM active=false ends sessions even when autoDeactivateUsers leaves the ban flag off.
		if (scimActive === false || banned === 1) {
			await db.delete(sessions).where(eq(sessions.userId, userId));
			await revokeUserMcpAccess(db, revocations, userId, "scim.deactivate");
		}

		const updatedRows = (await db
			.select()
			.from(users)
			.where(eq(users.id, userId))
			.limit(1)) as UserRow[];
		await writeScimAudit(
			"scim.user.update",
			`scim:users:${userId}`,
			userId,
			Math.round(performance.now() - auditStart),
		);
		return scimResponse(userRowToScim(updatedRows[0] as UserRow, baseUrlForPatch));
	}

	async function handleDeleteUser(_request: Request, userId: string): Promise<Response> {
		const auditStart = performance.now();
		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const row = rows[0];
		if (!row) return scimError("User not found", 404, "noTarget");

		await db.delete(sessions).where(eq(sessions.userId, userId));
		await revokeUserMcpAccess(db, revocations, userId, "scim.deprovision");
		if (autoDeactivateUsers) {
			const now = new Date();
			const meta = { ...(row.metadata ?? {}), "scim:active": false, "scim:deprovisioned": true };
			await db
				.update(users)
				.set({ banned: 1, metadata: meta, updatedAt: now })
				.where(eq(users.id, userId));
		} else {
			await db.delete(users).where(eq(users.id, userId));
		}

		if (onDeprovision) {
			await onDeprovision(userId);
		}

		await writeScimAudit(
			"scim.user.delete",
			`scim:users:${userId}`,
			userId,
			Math.round(performance.now() - auditStart),
		);
		return new Response(null, { status: 204 });
	}
	async function handleMe(request: Request): Promise<Response> {
		if (!resolveSelf) {
			return scimError(
				"Me endpoint requires a resolveSelf configuration callback",
				501,
				"invalidValue",
			);
		}

		let userId: string | null;
		try {
			userId = await resolveSelf(request);
		} catch {
			return scimError("resolveSelf threw while resolving the current user", 500);
		}

		if (!userId) {
			return scimError("No user is associated with this bearer token", 404, "noTarget");
		}

		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const row = rows[0];
		if (!row) {
			return scimError("Resolved user does not exist", 404, "noTarget");
		}

		return scimResponse(userRowToScim(row, getBaseUrl(request)));
	}

	return {
		handleListUsers,
		handleGetUser,
		handleCreateUser,
		handleReplaceUser,
		handlePatchUser,
		handleDeleteUser,
		handleMe,
	};
}
