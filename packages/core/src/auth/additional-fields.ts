/**
 * Additional user and session fields, stored in `user.metadata` and `session.metadata`.
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { additionalFields } from '@glinr/theauth/auth';
 *
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   plugins: [
 *     additionalFields({
 *       user: {
 *         plan:    { type: 'string', required: false, defaultValue: 'free' },
 *         credits: { type: 'number', required: false, defaultValue: 0 },
 *       },
 *     }),
 *   ],
 * });
 *
 * const mod = theauth.plugins.getContext().additionalFields as AdditionalFieldsModule;
 * await mod.setUserFields(userId, { plan: 'pro', credits: 100 });
 * const fields = await mod.getUserFields(userId);
 * // => { plan: 'pro', credits: 100 }
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { sessions, users } from "../db/schema.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import { databaseHooksFromConfig, withUserUpdate } from "../hooks/user-update-hooks.js";
import type { TheAuthPlugin } from "../plugin/types.js";

export interface FieldDefinition {
	type: "string" | "number" | "boolean" | "json";
	required?: boolean;
	defaultValue?: unknown;
}

export interface AdditionalFieldsConfig {
	user?: Record<string, FieldDefinition>;
	session?: Record<string, FieldDefinition>;
}

export interface ValidationResult {
	valid: boolean;
	errors?: string[];
}

export interface AdditionalFieldsModule {
	/** Returns the additional fields stored in `user.metadata` for a user. */
	getUserFields(userId: string): Promise<Record<string, unknown>>;
	/** Writes `fields` into `user.metadata`, merging with stored values. */
	setUserFields(userId: string, fields: Record<string, unknown>): Promise<void>;
	/** Returns the additional fields stored in `session.metadata` for a session. */
	getSessionFields(sessionId: string): Promise<Record<string, unknown>>;
	/** Writes `fields` into `session.metadata`, merging with stored values. */
	setSessionFields(sessionId: string, fields: Record<string, unknown>): Promise<void>;
	/** Validates a field map against the "user" or "session" schema. */
	validate(fields: Record<string, unknown>, schema: "user" | "session"): ValidationResult;
}

const TYPE_CHECKS: Record<FieldDefinition["type"], (v: unknown) => boolean> = {
	string: (v) => typeof v === "string",
	number: (v) => typeof v === "number",
	boolean: (v) => typeof v === "boolean",
	json: (v) => v !== null && v !== undefined,
};

function validateFields(
	fields: Record<string, unknown>,
	schema: Record<string, FieldDefinition> | undefined,
): ValidationResult {
	if (!schema) return { valid: true };

	const errors: string[] = [];

	for (const [key, def] of Object.entries(schema)) {
		if (def.required && !(key in fields)) {
			errors.push(`Field "${key}" is required`);
		}
	}

	for (const [key, value] of Object.entries(fields)) {
		const def = schema[key];
		if (!def) {
			errors.push(`Field "${key}" is not defined in the schema`);
			continue;
		}
		if (!TYPE_CHECKS[def.type](value)) {
			errors.push(`Field "${key}" must be of type ${def.type}`);
		}
	}

	return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

function applyDefaults(
	stored: Record<string, unknown>,
	schema: Record<string, FieldDefinition> | undefined,
): Record<string, unknown> {
	if (!schema) return stored;

	const result: Record<string, unknown> = { ...stored };
	for (const [key, def] of Object.entries(schema)) {
		if (!(key in result) && def.defaultValue !== undefined) {
			result[key] = def.defaultValue;
		}
	}
	return result;
}

export function createAdditionalFieldsModule(
	config: AdditionalFieldsConfig,
	db: Database,
	databaseHooks: DatabaseHookRunner = createDatabaseHookRunner(undefined),
): AdditionalFieldsModule {
	function validate(
		fields: Record<string, unknown>,
		schemaKey: "user" | "session",
	): ValidationResult {
		return validateFields(fields, schemaKey === "user" ? config.user : config.session);
	}

	async function getUserFields(userId: string): Promise<Record<string, unknown>> {
		const rows = await db
			.select({ metadata: users.metadata })
			.from(users)
			.where(eq(users.id, userId));

		const row = rows[0];
		const meta = row?.metadata ?? {};
		const stored =
			meta !== null &&
			typeof meta === "object" &&
			!Array.isArray(meta) &&
			"additionalFields" in meta &&
			meta.additionalFields !== null &&
			typeof meta.additionalFields === "object" &&
			!Array.isArray(meta.additionalFields)
				? (meta.additionalFields as Record<string, unknown>)
				: {};

		return applyDefaults(stored, config.user);
	}

	async function setUserFields(userId: string, fields: Record<string, unknown>): Promise<void> {
		const result = validate(fields, "user");
		if (!result.valid) {
			throw new Error(
				`AdditionalFieldsModule: validation failed: ${(result.errors ?? []).join(", ")}`,
			);
		}

		const rows = await db
			.select({ metadata: users.metadata })
			.from(users)
			.where(eq(users.id, userId));

		if (!rows[0]) {
			throw new Error(`AdditionalFieldsModule: user not found: ${userId}`);
		}

		const existing = (rows[0].metadata ?? {}) as Record<string, unknown>;
		const existingAdditional =
			existing.additionalFields !== null &&
			existing.additionalFields !== undefined &&
			typeof existing.additionalFields === "object" &&
			!Array.isArray(existing.additionalFields)
				? (existing.additionalFields as Record<string, unknown>)
				: {};

		const updatedMeta: Record<string, unknown> = {
			...existing,
			additionalFields: { ...existingAdditional, ...fields },
		};

		await withUserUpdate(
			databaseHooks,
			db,
			userId,
			{ metadata: updatedMeta },
			async (effective) => {
				await db
					.update(users)
					.set({ metadata: effective.metadata ?? updatedMeta, updatedAt: new Date() })
					.where(eq(users.id, userId));
			},
		);
	}

	async function getSessionFields(sessionId: string): Promise<Record<string, unknown>> {
		const rows = await db
			.select({ metadata: sessions.metadata })
			.from(sessions)
			.where(eq(sessions.id, sessionId));

		const row = rows[0];
		const meta = row?.metadata ?? {};
		const stored =
			meta !== null &&
			typeof meta === "object" &&
			!Array.isArray(meta) &&
			"additionalFields" in meta &&
			meta.additionalFields !== null &&
			typeof meta.additionalFields === "object" &&
			!Array.isArray(meta.additionalFields)
				? (meta.additionalFields as Record<string, unknown>)
				: {};

		return applyDefaults(stored, config.session);
	}

	async function setSessionFields(
		sessionId: string,
		fields: Record<string, unknown>,
	): Promise<void> {
		const result = validate(fields, "session");
		if (!result.valid) {
			throw new Error(
				`AdditionalFieldsModule: validation failed: ${(result.errors ?? []).join(", ")}`,
			);
		}

		const rows = await db
			.select({ metadata: sessions.metadata })
			.from(sessions)
			.where(eq(sessions.id, sessionId));

		if (!rows[0]) {
			throw new Error(`AdditionalFieldsModule: session not found: ${sessionId}`);
		}

		const existing = (rows[0].metadata ?? {}) as Record<string, unknown>;
		const existingAdditional =
			existing.additionalFields !== null &&
			existing.additionalFields !== undefined &&
			typeof existing.additionalFields === "object" &&
			!Array.isArray(existing.additionalFields)
				? (existing.additionalFields as Record<string, unknown>)
				: {};

		const updatedMeta: Record<string, unknown> = {
			...existing,
			additionalFields: { ...existingAdditional, ...fields },
		};

		await db.update(sessions).set({ metadata: updatedMeta }).where(eq(sessions.id, sessionId));
	}

	return { getUserFields, setUserFields, getSessionFields, setSessionFields, validate };
}

export function additionalFields(config: AdditionalFieldsConfig = {}): TheAuthPlugin {
	return {
		id: "theauth-additional-fields",

		async init(ctx) {
			const mod = createAdditionalFieldsModule(config, ctx.db, databaseHooksFromConfig(ctx.config));

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/users/fields",
				metadata: {
					requireAuth: true,
					description: "Get additional fields for a user",
				},
				async handler(request, endpointCtx) {
					// The signed-in user's own fields only. A different `userId` is refused.
					const user = await endpointCtx.getUser(request);
					if (!user) return jsonResponse({ error: "Authentication required" }, 401);
					const requested = new URL(request.url).searchParams.get("userId");
					if (requested && requested !== user.id) {
						return jsonResponse({ error: "You can only read your own fields" }, 403);
					}
					const userId = user.id;

					try {
						const fields = await mod.getUserFields(userId);
						return jsonResponse({ fields });
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to get user fields" },
							500,
						);
					}
				},
			});

			ctx.addEndpoint({
				method: "PUT",
				path: "/auth/users/fields",
				metadata: {
					requireAuth: true,
					description: "Set additional fields on a user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) return jsonResponse({ error: "Authentication required" }, 401);
					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						return jsonResponse({ error: "Invalid JSON body" }, 400);
					}

					// The signed-in user's own fields only. A different body `userId` is refused.
					if (body.userId !== undefined && body.userId !== user.id) {
						return jsonResponse({ error: "You can only update your own fields" }, 403);
					}
					const userId = user.id;

					const fields =
						body.fields !== null &&
						body.fields !== undefined &&
						typeof body.fields === "object" &&
						!Array.isArray(body.fields)
							? (body.fields as Record<string, unknown>)
							: null;

					if (!fields) {
						return jsonResponse({ error: "Missing or invalid field: fields" }, 400);
					}

					try {
						await mod.setUserFields(userId, fields);
						return jsonResponse({ updated: true });
					} catch (err) {
						const message = err instanceof Error ? err.message : "Update failed";
						const status = message.includes("not found")
							? 404
							: message.includes("validation failed")
								? 422
								: 500;
						return jsonResponse({ error: message }, status);
					}
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/fields/validate",
				metadata: {
					description: "Validate fields against the user or session schema",
				},
				async handler(request, _endpointCtx) {
					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						return jsonResponse({ error: "Invalid JSON body" }, 400);
					}

					const schema = body.schema === "user" || body.schema === "session" ? body.schema : null;
					if (!schema) {
						return jsonResponse(
							{ error: 'Missing or invalid field: schema (must be "user" or "session")' },
							400,
						);
					}

					const fields =
						body.fields !== null &&
						body.fields !== undefined &&
						typeof body.fields === "object" &&
						!Array.isArray(body.fields)
							? (body.fields as Record<string, unknown>)
							: null;

					if (!fields) {
						return jsonResponse({ error: "Missing or invalid field: fields" }, 400);
					}

					const result = mod.validate(fields, schema);
					return jsonResponse(result, result.valid ? 200 : 422);
				},
			});

			return {
				context: { additionalFields: mod },
			};
		},
	};
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}
