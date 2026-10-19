import { eq, or } from "drizzle-orm";
import { sessions, users } from "../db/schema.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import { withUserUpdate } from "../hooks/user-update-hooks.js";
import {
	generateId,
	getBaseUrl,
	SCHEMA_ENTERPRISE,
	SCHEMA_PATCH,
	scimError,
	scimResponse,
	userRowToScim,
} from "./scim-helpers.js";
import { applyPatchOps, ScimPatchError } from "./scim-patch.js";
import type { PatchBody, ScimHandlerContext, ScimUser, UserRow } from "./scim-types.js";
import { createScimListHandler } from "./scim-users-list.js";
import { revokeUserMcpAccess } from "./user-revocation.js";

export function createScimUserHandlers(ctx: ScimHandlerContext) {
	const { db, writeScimAudit, config, revocations } = ctx;
	const databaseHooks = ctx.databaseHooks ?? createDatabaseHookRunner(undefined);
	const {
		autoCreateUsers = true,
		autoDeactivateUsers = true,
		onProvision,
		onDeprovision,
		resolveSelf,
	} = config;

	const handleListUsers = createScimListHandler(ctx);

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

		let storedEmail = primaryEmail;
		let storedName = displayName;
		let storedMetadata = metadata;
		if (databaseHooks.has("user", "create")) {
			// Runs ahead of the insert. A DatabaseHookError aborts provisioning.
			const hooked = await databaseHooks.before("user", "create", {
				id,
				email: primaryEmail,
				name: displayName,
				metadata,
			});
			storedEmail = hooked.email;
			storedName = hooked.name;
			storedMetadata = hooked.metadata ?? {};
			if (storedEmail !== primaryEmail) {
				const clash = await db.select().from(users).where(eq(users.email, storedEmail)).limit(1);
				if (clash.length > 0) return scimError("User already exists", 409, "uniqueness");
			}
		}

		await db.insert(users).values({
			id,
			email: storedEmail,
			name: storedName,
			username: userName !== primaryEmail ? userName : null,
			externalId,
			externalProvider: "scim",
			banned: active ? 0 : 1,
			metadata: storedMetadata,
			createdAt: now,
			updatedAt: now,
		});

		const createdRows = (await db
			.select()
			.from(users)
			.where(eq(users.id, id))
			.limit(1)) as UserRow[];
		const created = createdRows[0] as UserRow;
		await databaseHooks.after("user", "create", {
			id,
			email: created.email,
			name: created.name ?? null,
			metadata: created.metadata ?? null,
		});

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
		await withUserUpdate(
			databaseHooks,
			db,
			userId,
			{ email: primaryEmail, name: displayName ?? null, metadata },
			async (hooked) => {
				await db
					.update(users)
					.set({
						username: userName !== primaryEmail ? userName : existing.username,
						externalId,
						banned: active ? 0 : 1,
						updatedAt: now,
						...hooked,
					})
					.where(eq(users.id, userId));
			},
		);
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
		await withUserUpdate(
			databaseHooks,
			db,
			userId,
			{ email, name, metadata: updatedMeta },
			async (hooked) => {
				await db
					.update(users)
					.set({ username, banned, externalId, updatedAt: now, ...hooked })
					.where(eq(users.id, userId));
			},
		);
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
			await withUserUpdate(databaseHooks, db, userId, { metadata: meta }, async (hooked) => {
				await db
					.update(users)
					.set({ banned: 1, updatedAt: now, ...hooked })
					.where(eq(users.id, userId));
			});
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
