/**
 * SCIM 2.0 directory sync for TheAuth.
 *
 * Implements RFC 7644 (SCIM 2.0 protocol) to allow enterprise identity
 * providers (Okta, Azure AD, Google Workspace) to provision and deprovision
 * users and groups automatically.
 *
 * Users map to theauth_users. Groups map to theauth_organizations.
 *
 * @example
 * ```typescript
 * import { createScimModule } from '@glinr/theauth/auth';
 *
 * const scim = createScimModule({
 *   bearerToken: process.env.SCIM_TOKEN,
 *   onProvision: async (user) => {
 *     console.log('Provisioned:', user.userName);
 *   },
 * }, db);
 *
 * // In your request handler:
 * const response = await scim.handleRequest(request);
 * ```
 */

import { and, eq, like, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { organizations, orgMembers, users } from "../db/schema.js";
import type { FilterAst } from "./scim-filter.js";
import { evaluateFilter, parseFilter, ScimFilterError } from "./scim-filter.js";
import { applyPatchOps, ScimPatchError } from "./scim-patch.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ScimConfig {
	/** Bearer token for SCIM API authentication */
	bearerToken: string;
	/** Whether to auto-create users on provision (default: true) */
	autoCreateUsers?: boolean;
	/** Whether to auto-deactivate users on deprovision (default: true) */
	autoDeactivateUsers?: boolean;
	/** Callback when user is provisioned */
	onProvision?: (user: ScimUser) => Promise<void>;
	/** Callback when user is deprovisioned */
	onDeprovision?: (userId: string) => Promise<void>;
}

export interface ScimUser {
	id: string;
	userName: string;
	name?: { givenName?: string; familyName?: string };
	emails?: Array<{ value: string; primary?: boolean }>;
	active?: boolean;
	externalId?: string;
}

export interface ScimGroup {
	id: string;
	displayName: string;
	externalId?: string;
	members?: Array<{ value: string; display?: string }>;
}

export interface ScimModule {
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal row types
// ---------------------------------------------------------------------------

interface UserRow {
	id: string;
	email: string;
	name: string | null;
	username: string | null;
	externalId: string | null;
	externalProvider: string | null;
	banned: number;
	metadata: Record<string, unknown> | null;
	createdAt: Date;
	updatedAt: Date;
}

interface OrgRow {
	id: string;
	name: string;
	slug: string;
	ownerId: string;
	metadata: Record<string, unknown> | null;
	createdAt: Date;
	updatedAt: Date;
}

interface OrgMemberRow {
	id: string;
	orgId: string;
	userId: string;
	role: string;
	joinedAt: Date;
}

// ---------------------------------------------------------------------------
// SCIM constants
// ---------------------------------------------------------------------------

const SCIM_CONTENT_TYPE = "application/scim+json";

const SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";

const SCHEMA_SP_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scimResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": SCIM_CONTENT_TYPE },
	});
}

function scimError(detail: string, status: number, scimType?: string): Response {
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

function generateId(): string {
	return crypto.randomUUID().replace(/-/g, "");
}

function toIso(date: Date): string {
	return date.toISOString();
}

/** Extract the last path segment after the given prefix segment. */
function extractId(pathname: string, prefix: string): string | null {
	const segments = pathname.split("/").filter(Boolean);
	const idx = segments.indexOf(prefix);
	if (idx === -1 || idx + 1 >= segments.length) return null;
	const seg = segments[idx + 1];
	return seg !== undefined ? decodeURIComponent(seg) : null;
}

// ---------------------------------------------------------------------------
// Mapping functions
// ---------------------------------------------------------------------------

function userRowToScim(row: UserRow, baseUrl: string): Record<string, unknown> {
	const primaryEmail = row.email;
	const meta = row.metadata ?? {};
	const active = meta["scim:active"] !== false && row.banned === 0;

	return {
		schemas: [SCHEMA_USER],
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
}

function orgRowToScim(
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

// ---------------------------------------------------------------------------
// Filter parsing (RFC 7644 §3.4.2.2)
// Full grammar lives in scim-filter.ts. We keep a legacy clause-array shape
// here so the SQL translator below stays simple for the common Okta filters
// (pure "and" of eq/co/sw/pr). For expressions that do not flatten to that
// shape (or / not / value-paths / ne / ew / gt / ge / lt / le) the caller
// falls back to in-memory evaluation against the serialized resource.
// ---------------------------------------------------------------------------

type LegacyFilterOp = "eq" | "co" | "sw" | "pr";

interface FilterClause {
	attribute: string;
	op: LegacyFilterOp;
	value?: string;
}

/**
 * Try to express the AST as a flat `and` of clauses the SQL translator
 * understands. Returns `null` when the filter is richer than that.
 */
function flattenToLegacyClauses(ast: FilterAst): FilterClause[] | null {
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

function attrKey(path: string[]): string {
	return path.join(".").toLowerCase();
}

/**
 * Parse a SCIM filter string via the RFC 7644 AST and attempt to flatten it
 * to a legacy clause list. Returns `{ clauses: null }` when the filter is
 * structurally fine but too rich for the SQL path.
 *
 * @throws ScimFilterError when the filter is malformed.
 */
function parseScimFilter(filter: string): { ast: FilterAst; clauses: FilterClause[] | null } {
	const ast = parseFilter(filter);
	const clauses = flattenToLegacyClauses(ast);
	return { ast, clauses };
}

// ---------------------------------------------------------------------------
// PATCH operation types (RFC 7644 §3.5.2)
// ---------------------------------------------------------------------------

interface PatchOperation {
	op: "add" | "replace" | "remove";
	path?: string;
	value?: unknown;
}

interface PatchBody {
	schemas: string[];
	Operations: PatchOperation[];
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createScimModule(config: ScimConfig, db: Database): ScimModule {
	const {
		bearerToken,
		autoCreateUsers = true,
		autoDeactivateUsers = true,
		onProvision,
		onDeprovision,
	} = config;

	// -------------------------------------------------------------------------
	// Auth guard
	// -------------------------------------------------------------------------

	function isAuthorized(request: Request): boolean {
		const authHeader = request.headers.get("Authorization");
		if (!authHeader) return false;
		const [scheme, token] = authHeader.split(" ");
		return scheme?.toLowerCase() === "bearer" && token === bearerToken;
	}

	// -------------------------------------------------------------------------
	// Base URL extraction
	// -------------------------------------------------------------------------

	function getBaseUrl(request: Request): string {
		const url = new URL(request.url);
		return `${url.protocol}//${url.host}`;
	}

	// -------------------------------------------------------------------------
	// User handlers
	// -------------------------------------------------------------------------

	async function handleListUsers(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const filterParam = url.searchParams.get("filter") ?? "";
		const startIndex = Math.max(1, parseInt(url.searchParams.get("startIndex") ?? "1", 10));
		const count = Math.min(200, parseInt(url.searchParams.get("count") ?? "100", 10));
		const baseUrl = getBaseUrl(request);

		// Parse filter AST once. Simple and-of-clauses filters take a fast SQL
		// path. Complex filters (or / not / value-paths / advanced ops) fall
		// back to broad fetch + in-memory evaluation.
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

		if (conditions !== null) {
			// Fast path — SQL filter covers the entire expression.
			const countRows = await db
				.select({ count: sql<number>`count(*)` })
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

		// Fallback — evaluate AST against the SCIM-shaped resource in memory.
		const allRows = (await db.select().from(users)) as UserRow[];
		const mapped = allRows.map((r) => ({ row: r, scim: userRowToScim(r, baseUrl) }));
		const matched = ast
			? mapped.filter(({ scim }) => evaluateFilter(ast as FilterAst, scim))
			: mapped;
		const totalResults = matched.length;
		const page = matched.slice(startIndex - 1, startIndex - 1 + count);

		return scimResponse({
			schemas: [SCHEMA_LIST],
			totalResults,
			startIndex,
			itemsPerPage: page.length,
			Resources: page.map((p) => p.scim),
		});
	}

	function buildUserSqlConditions(list: FilterClause[]): ReturnType<typeof eq>[] | null {
		const conds: ReturnType<typeof eq>[] = [];
		for (const clause of list) {
			if (clause.attribute === "username" && clause.value !== undefined) {
				if (clause.op === "eq") {
					conds.push(
						sql`(${users.username} = ${clause.value} OR ${users.email} = ${clause.value})`,
					);
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
			// Unknown attribute — cannot SQL-translate, request in-memory fallback.
			return null;
		}
		return conds;
	}

	async function handleGetUser(request: Request, userId: string): Promise<Response> {
		const baseUrl = getBaseUrl(request);
		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const row = rows[0];
		if (!row) return scimError("User not found", 404, "noTarget");
		return scimResponse(userRowToScim(row, baseUrl));
	}

	async function handleCreateUser(request: Request): Promise<Response> {
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

		// Extract email
		const emailsRaw = body.emails as Array<{ value: string; primary?: boolean }> | undefined;
		const primaryEmail =
			emailsRaw?.find((e) => e.primary)?.value ?? emailsRaw?.[0]?.value ?? userName;

		// Extract name parts
		const nameRaw = body.name as
			| { givenName?: string; familyName?: string; formatted?: string }
			| undefined;
		const givenName = nameRaw?.givenName;
		const familyName = nameRaw?.familyName;
		const nameFromParts = [givenName, familyName].filter(Boolean).join(" ") || null;
		const displayName = (body.displayName as string | undefined) ?? nameFromParts;

		const externalId = (body.externalId as string | undefined) ?? null;
		const active = (body.active as boolean | undefined) ?? true;

		// Check if user already exists by email or userName
		const existing = (await db
			.select()
			.from(users)
			.where(sql`${users.email} = ${primaryEmail} OR ${users.username} = ${userName}`)
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
		return scimResponse(userRowToScim(created, baseUrl), 201);
	}

	async function handleReplaceUser(request: Request, userId: string): Promise<Response> {
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

		const updatedRows = (await db
			.select()
			.from(users)
			.where(eq(users.id, userId))
			.limit(1)) as UserRow[];
		const baseUrl = getBaseUrl(request);
		return scimResponse(userRowToScim(updatedRows[0] as UserRow, baseUrl));
	}

	async function handlePatchUser(request: Request, userId: string): Promise<Response> {
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

		// Extract mutated fields back from the SCIM view.
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

		const updatedRows = (await db
			.select()
			.from(users)
			.where(eq(users.id, userId))
			.limit(1)) as UserRow[];
		return scimResponse(userRowToScim(updatedRows[0] as UserRow, baseUrlForPatch));
	}

	async function handleDeleteUser(_request: Request, userId: string): Promise<Response> {
		const rows = (await db.select().from(users).where(eq(users.id, userId)).limit(1)) as UserRow[];
		const row = rows[0];
		if (!row) return scimError("User not found", 404, "noTarget");

		if (autoDeactivateUsers) {
			// Soft delete: deactivate rather than destroy
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

		return new Response(null, { status: 204 });
	}

	// -------------------------------------------------------------------------
	// Group handlers
	// -------------------------------------------------------------------------

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
			.where(sql`${users.id} IN ${ids}`)) as { id: string; email: string }[];
		return new Map(emailRows.map((r) => [r.id, r.email]));
	}

	async function handleListGroups(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const filterParam = url.searchParams.get("filter") ?? "";
		const startIndex = Math.max(1, parseInt(url.searchParams.get("startIndex") ?? "1", 10));
		const count = Math.min(200, parseInt(url.searchParams.get("count") ?? "100", 10));
		const baseUrl = getBaseUrl(request);

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

		if (conditions !== null) {
			const countRows = await db
				.select({ count: sql<number>`count(*)` })
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

		// In-memory fallback for complex filters.
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
		const totalResults = matched.length;
		const page = matched.slice(startIndex - 1, startIndex - 1 + count);

		return scimResponse({
			schemas: [SCHEMA_LIST],
			totalResults,
			startIndex,
			itemsPerPage: page.length,
			Resources: page.map((p) => p.scim),
		});
	}

	function buildGroupSqlConditions(list: FilterClause[]): ReturnType<typeof eq>[] | null {
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

		// Generate a URL-safe slug
		const slug = displayName
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-|-$/g, "")
			.slice(0, 50);

		// Ensure slug uniqueness
		const existingSlug = (await db
			.select({ id: organizations.id })
			.from(organizations)
			.where(eq(organizations.slug, slug))
			.limit(1)) as { id: string }[];

		const finalSlug = existingSlug.length > 0 ? `${slug}-${generateId().slice(0, 8)}` : slug;

		const id = `org_scim_${generateId()}`;
		const now = new Date();

		// SCIM groups need an owner — use a system placeholder stored in metadata
		// The ownerId column is not null, so we use a convention: store "scim" owner reference
		// We require at least one member in the members array to serve as owner,
		// or fall back to the first user in the DB.
		const membersRaw = body.members as Array<{ value: string }> | undefined;
		const ownerCandidateId = membersRaw?.[0]?.value;

		let ownerId: string;
		if (ownerCandidateId) {
			ownerId = ownerCandidateId;
		} else {
			// Fall back to first user in DB
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

		// Add initial members
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
		return scimResponse(
			orgRowToScim(orgRows[0] as OrgRow, createdMembers, memberEmails, baseUrl),
			201,
		);
	}

	async function handleReplaceGroup(request: Request, groupId: string): Promise<Response> {
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

		// Replace member list if provided
		if (membersRaw !== undefined) {
			await db.delete(orgMembers).where(eq(orgMembers.orgId, groupId));
			if (membersRaw.length > 0) {
				const memberInserts = membersRaw.map((m) => ({
					id: `om_scim_${generateId()}`,
					orgId: groupId,
					userId: m.value,
					role: "member",
					joinedAt: now,
				}));
				await db.insert(orgMembers).values(memberInserts);
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
		return scimResponse(orgRowToScim(updatedOrg[0] as OrgRow, members, memberEmails, baseUrl));
	}

	async function handlePatchGroup(request: Request, groupId: string): Promise<Response> {
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
				// Could be array of members or object with displayName
				if (Array.isArray(val)) {
					for (const m of val) {
						if (typeof m.value === "string") {
							// Check if already a member
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
					// Remove specific members from value array
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
		return scimResponse(orgRowToScim(updatedOrg[0] as OrgRow, members, memberEmails, baseUrl));
	}

	async function handleDeleteGroup(_request: Request, groupId: string): Promise<Response> {
		const orgRows = (await db
			.select()
			.from(organizations)
			.where(eq(organizations.id, groupId))
			.limit(1)) as OrgRow[];
		if (orgRows.length === 0) return scimError("Group not found", 404, "noTarget");

		await db.delete(orgMembers).where(eq(orgMembers.orgId, groupId));
		await db.delete(organizations).where(eq(organizations.id, groupId));

		return new Response(null, { status: 204 });
	}

	// -------------------------------------------------------------------------
	// Discovery endpoints
	// -------------------------------------------------------------------------

	function handleServiceProviderConfig(request: Request): Response {
		const baseUrl = getBaseUrl(request);
		return scimResponse({
			schemas: [SCHEMA_SP_CONFIG],
			documentationUri: "https://theauth.dev/docs/scim",
			patch: { supported: true },
			bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
			filter: { supported: true, maxResults: 200 },
			changePassword: { supported: false },
			sort: { supported: false },
			etag: { supported: false },
			authenticationSchemes: [
				{
					type: "oauthbearertoken",
					name: "OAuth Bearer Token",
					description: "Authentication scheme using OAuth Bearer Token",
					specUri: "https://www.rfc-editor.org/rfc/rfc6750",
					primary: true,
				},
			],
			meta: {
				resourceType: "ServiceProviderConfig",
				location: `${baseUrl}/scim/v2/ServiceProviderConfig`,
			},
		});
	}

	function handleSchemas(request: Request): Response {
		const baseUrl = getBaseUrl(request);
		return scimResponse({
			schemas: [SCHEMA_LIST],
			totalResults: 2,
			startIndex: 1,
			itemsPerPage: 2,
			Resources: [
				{
					schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
					id: SCHEMA_USER,
					name: "User",
					description: "User Account",
					attributes: [
						{ name: "userName", type: "string", required: true, uniqueness: "server" },
						{ name: "displayName", type: "string", required: false },
						{
							name: "name",
							type: "complex",
							required: false,
							subAttributes: [
								{ name: "givenName", type: "string" },
								{ name: "familyName", type: "string" },
								{ name: "formatted", type: "string" },
							],
						},
						{ name: "emails", type: "complex", multiValued: true, required: false },
						{ name: "active", type: "boolean", required: false },
						{ name: "externalId", type: "string", required: false },
					],
					meta: {
						resourceType: "Schema",
						location: `${baseUrl}/scim/v2/Schemas/${SCHEMA_USER}`,
					},
				},
				{
					schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
					id: SCHEMA_GROUP,
					name: "Group",
					description: "Group",
					attributes: [
						{ name: "displayName", type: "string", required: true },
						{ name: "members", type: "complex", multiValued: true, required: false },
						{ name: "externalId", type: "string", required: false },
					],
					meta: {
						resourceType: "Schema",
						location: `${baseUrl}/scim/v2/Schemas/${SCHEMA_GROUP}`,
					},
				},
			],
		});
	}

	function handleResourceTypes(request: Request): Response {
		const baseUrl = getBaseUrl(request);
		return scimResponse({
			schemas: [SCHEMA_LIST],
			totalResults: 2,
			startIndex: 1,
			itemsPerPage: 2,
			Resources: [
				{
					schemas: [SCHEMA_RESOURCE_TYPE],
					id: "User",
					name: "User",
					endpoint: "/Users",
					description: "User Account",
					schema: SCHEMA_USER,
					meta: {
						resourceType: "ResourceType",
						location: `${baseUrl}/scim/v2/ResourceTypes/User`,
					},
				},
				{
					schemas: [SCHEMA_RESOURCE_TYPE],
					id: "Group",
					name: "Group",
					endpoint: "/Groups",
					description: "Group",
					schema: SCHEMA_GROUP,
					meta: {
						resourceType: "ResourceType",
						location: `${baseUrl}/scim/v2/ResourceTypes/Group`,
					},
				},
			],
		});
	}

	// -------------------------------------------------------------------------
	// Request router
	// -------------------------------------------------------------------------

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		// Only handle /scim/v2/ paths
		if (!pathname.includes("/scim/v2/")) return null;

		// Auth check on all SCIM routes
		if (!isAuthorized(request)) {
			return scimError("Unauthorized: valid Bearer token required", 401);
		}

		const method = request.method.toUpperCase();

		// Discovery — no ID extraction needed
		if (method === "GET" && pathname.endsWith("/scim/v2/ServiceProviderConfig")) {
			return handleServiceProviderConfig(request);
		}
		if (method === "GET" && pathname.endsWith("/scim/v2/Schemas")) {
			return handleSchemas(request);
		}
		if (method === "GET" && pathname.endsWith("/scim/v2/ResourceTypes")) {
			return handleResourceTypes(request);
		}

		// Users collection
		if (method === "GET" && /\/scim\/v2\/Users\/?$/.test(pathname)) {
			return handleListUsers(request);
		}
		if (method === "POST" && /\/scim\/v2\/Users\/?$/.test(pathname)) {
			return handleCreateUser(request);
		}

		// Users by ID
		const userId = extractId(pathname, "Users");
		if (userId) {
			if (method === "GET") return handleGetUser(request, userId);
			if (method === "PUT") return handleReplaceUser(request, userId);
			if (method === "PATCH") return handlePatchUser(request, userId);
			if (method === "DELETE") return handleDeleteUser(request, userId);
		}

		// Groups collection
		if (method === "GET" && /\/scim\/v2\/Groups\/?$/.test(pathname)) {
			return handleListGroups(request);
		}
		if (method === "POST" && /\/scim\/v2\/Groups\/?$/.test(pathname)) {
			return handleCreateGroup(request);
		}

		// Groups by ID
		const groupId = extractId(pathname, "Groups");
		if (groupId) {
			if (method === "GET") return handleGetGroup(request, groupId);
			if (method === "PUT") return handleReplaceGroup(request, groupId);
			if (method === "PATCH") return handlePatchGroup(request, groupId);
			if (method === "DELETE") return handleDeleteGroup(request, groupId);
		}

		return null;
	}

	return { handleRequest };
}
