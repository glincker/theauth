/**
 * Additional user/session fields plugin for TheAuth.
 *
 * Lets callers extend the user and session schemas with typed custom fields
 * without writing any database migrations.  Fields are stored in the existing
 * `user.metadata` or `session.metadata` JSON columns.
 *
 * Field types: `string`, `number`, `boolean`, `json`.
 * Required fields must be present when calling `setUserFields`.
 * Fields not in the schema are rejected during `validate()`.
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { additionalFields } from '@glinr/theauth/auth';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
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
 * const mod = kavach.plugins.getContext().additionalFields as AdditionalFieldsModule;
 * await mod.setUserFields(userId, { plan: 'pro', credits: 100 });
 * const fields = await mod.getUserFields(userId);
 * // => { plan: 'pro', credits: 100 }
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { sessions, users } from "../db/schema.js";
import type { KavachPlugin } from "../plugin/types.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface FieldDefinition {
	type: "string" | "number" | "boolean" | "json";
	required?: boolean;
	defaultValue?: unknown;
}

export interface AdditionalFieldsConfig {
	/** Custom fields for users (stored in user.metadata). */
	user?: Record<string, FieldDefinition>;
	/** Custom fields for sessions (stored in session.metadata). */
	session?: Record<string, FieldDefinition>;
}

export interface ValidationResult {
	valid: boolean;
	errors?: string[];
}

export interface AdditionalFieldsModule {
	/**
	 * Return the additional fields stored in `user.metadata` for the given user.
	 *
	 * Fields missing from the stored metadata are filled with their `defaultValue`
	 * (if one is defined in the schema).
	 */
	getUserFields(userId: string): Promise<Record<string, unknown>>;
	/**
	 * Write `fields` into `user.metadata`, merging with any already-stored values.
	 *
	 * Validates against the `user` schema before writing.
	 * Throws when the user does not exist or validation fails.
	 */
	setUserFields(userId: string, fields: Record<string, unknown>): Promise<void>;
	/**
	 * Return the additional fields stored in `session.metadata` for the given session.
	 */
	getSessionFields(sessionId: string): Promise<Record<string, unknown>>;
	/**
	 * Write `fields` into `session.metadata`, merging with any already-stored values.
	 *
	 * Validates against the `session` schema before writing.
	 * Throws when the session does not exist or validation fails.
	 */
	setSessionFields(sessionId: string, fields: Record<string, unknown>): Promise<void>;
	/**
	 * Validate a field map against the "user" or "session" schema.
	 *
	 * Returns `{ valid: true }` on success or `{ valid: false, errors: [...] }` on
	 * failure.  Does not throw.
	 */
	validate(fields: Record<string, unknown>, schema: "user" | "session"): ValidationResult;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

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

	// Check required fields are present
	for (const [key, def] of Object.entries(schema)) {
		if (def.required && !(key in fields)) {
			errors.push(`Field "${key}" is required`);
		}
	}

	// Check provided fields are in schema and match the declared type
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

// ---------------------------------------------------------------------------
// Default value hydration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createAdditionalFieldsModule(
	config: AdditionalFieldsConfig,
	db: Database,
): AdditionalFieldsModule {
	function validate(
		fields: Record<string, unknown>,
		schemaKey: "user" | "session",
	): ValidationResult {
		return validateFields(fields, schemaKey === "user" ? config.user : config.session);
	}

	// ── User fields ────────────────────────────────────────────────────────

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
				`AdditionalFieldsModule: validation failed — ${(result.errors ?? []).join(", ")}`,
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

		await db
			.update(users)
			.set({ metadata: updatedMeta, updatedAt: new Date() })
			.where(eq(users.id, userId));
	}

	// ── Session fields ─────────────────────────────────────────────────────

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
				`AdditionalFieldsModule: validation failed — ${(result.errors ?? []).join(", ")}`,
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

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function additionalFields(config: AdditionalFieldsConfig = {}): KavachPlugin {
	return {
		id: "kavach-additional-fields",

		async init(ctx) {
			const mod = createAdditionalFieldsModule(config, ctx.db);

			// GET /auth/users/fields?userId=<id>
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/users/fields",
				metadata: {
					requireAuth: true,
					description: "Get additional fields for a user",
				},
				async handler(request, _endpointCtx) {
					const url = new URL(request.url);
					const userId = url.searchParams.get("userId");
					if (!userId) {
						return jsonResponse({ error: "Missing required query parameter: userId" }, 400);
					}

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

			// PUT /auth/users/fields
			ctx.addEndpoint({
				method: "PUT",
				path: "/auth/users/fields",
				metadata: {
					requireAuth: true,
					description: "Set additional fields on a user",
				},
				async handler(request, _endpointCtx) {
					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						return jsonResponse({ error: "Invalid JSON body" }, 400);
					}

					const userId = typeof body.userId === "string" ? body.userId : null;
					if (!userId) {
						return jsonResponse({ error: "Missing required field: userId" }, 400);
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

			// POST /auth/fields/validate
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}
