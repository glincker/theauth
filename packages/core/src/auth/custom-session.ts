/**
 * Custom session fields plugin for TheAuth.
 *
 * Lets callers attach arbitrary data to sessions at creation time and read or
 * update that data later.  Everything is stored in the existing
 * `session.metadata.custom` sub-key — no new database columns are required.
 *
 * Two integration points:
 *
 * 1. `defaultFields` — merged into every new session automatically.
 * 2. `onSessionCreate` — async callback that receives the userId (and
 *    optionally the originating Request) and returns additional fields to
 *    merge.  Runs once per session, during the plugin's `onSessionCreate` hook.
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { customSession } from '@glinr/theauth/auth';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   plugins: [
 *     customSession({
 *       defaultFields: { theme: 'dark' },
 *       onSessionCreate: async (userId) => ({ lastSeen: Date.now() }),
 *     }),
 *   ],
 * });
 *
 * // After a session is created via kavach.auth.session.create(...)
 * const mod = kavach.plugins.getContext().customSession as CustomSessionModule;
 * const fields = await mod.getSessionFields(session.id);
 * // => { theme: 'dark', lastSeen: 1234567890 }
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { sessions } from "../db/schema.js";
import type { KavachPlugin } from "../plugin/types.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface CustomSessionConfig {
	/** Fields merged into every new session's metadata.custom on creation. */
	defaultFields?: Record<string, unknown>;
	/**
	 * Hook called when a new session is being created.
	 *
	 * The return value is merged into `session.metadata.custom` alongside any
	 * `defaultFields`.  If both define the same key, the hook's value wins.
	 */
	onSessionCreate?: (userId: string, request?: Request) => Promise<Record<string, unknown>>;
}

export interface CustomSessionModule {
	/**
	 * Return the custom fields stored in `session.metadata.custom`.
	 *
	 * Returns `null` when the session does not exist or has no custom data.
	 */
	getSessionFields(sessionId: string): Promise<Record<string, unknown> | null>;
	/**
	 * Merge `fields` into `session.metadata.custom`, overwriting any keys that
	 * already exist.  Existing keys not present in `fields` are preserved.
	 */
	updateSessionFields(sessionId: string, fields: Record<string, unknown>): Promise<void>;
}

// ---------------------------------------------------------------------------
// Module factory (used directly or via the KavachPlugin wrapper below)
// ---------------------------------------------------------------------------

export function createCustomSessionModule(
	_config: CustomSessionConfig,
	db: Database,
): CustomSessionModule {
	async function getSessionFields(sessionId: string): Promise<Record<string, unknown> | null> {
		const rows = await db
			.select({ metadata: sessions.metadata })
			.from(sessions)
			.where(eq(sessions.id, sessionId));

		const row = rows[0];
		if (!row) return null;

		const meta = row.metadata;
		if (meta === null || meta === undefined) return null;

		const custom = (meta as Record<string, unknown>).custom;
		if (custom === undefined || custom === null) return null;
		if (typeof custom !== "object" || Array.isArray(custom)) return null;

		return custom as Record<string, unknown>;
	}

	async function updateSessionFields(
		sessionId: string,
		fields: Record<string, unknown>,
	): Promise<void> {
		const rows = await db
			.select({ metadata: sessions.metadata })
			.from(sessions)
			.where(eq(sessions.id, sessionId));

		const row = rows[0];
		if (!row) {
			throw new Error(`CustomSessionModule: session not found: ${sessionId}`);
		}

		const existing = (row.metadata ?? {}) as Record<string, unknown>;
		const existingCustom =
			existing.custom !== null &&
			existing.custom !== undefined &&
			typeof existing.custom === "object" &&
			!Array.isArray(existing.custom)
				? (existing.custom as Record<string, unknown>)
				: {};

		const updatedMeta: Record<string, unknown> = {
			...existing,
			custom: { ...existingCustom, ...fields },
		};

		await db.update(sessions).set({ metadata: updatedMeta }).where(eq(sessions.id, sessionId));
	}

	return { getSessionFields, updateSessionFields };
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function customSession(config: CustomSessionConfig = {}): KavachPlugin {
	return {
		id: "kavach-custom-session",

		hooks: {
			/**
			 * Fired by the plugin runner after a session record is inserted.
			 *
			 * Merges defaultFields + onSessionCreate result into
			 * `session.metadata.custom`.  The session row already exists in the
			 * database at this point so we can issue an UPDATE.
			 */
			async onSessionCreate(userId: string): Promise<Record<string, unknown> | undefined> {
				const base = config.defaultFields ?? {};
				const dynamic = config.onSessionCreate ? await config.onSessionCreate(userId) : {};
				const merged = { ...base, ...dynamic };

				// Return the custom key so the runner can merge it into metadata.
				// We signal the presence of custom fields via the return value.
				if (Object.keys(merged).length === 0) return undefined;
				return { custom: merged };
			},
		},

		async init(ctx) {
			const mod = createCustomSessionModule(config, ctx.db);

			// GET /auth/session/:id/fields — read custom fields from a session
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/session/fields",
				metadata: {
					requireAuth: true,
					description: "Get custom fields for the authenticated session",
				},
				async handler(request, _endpointCtx) {
					// Expect ?sessionId=<id> query param
					const url = new URL(request.url);
					const sessionId = url.searchParams.get("sessionId");
					if (!sessionId) {
						return jsonResponse({ error: "Missing required query parameter: sessionId" }, 400);
					}

					try {
						const fields = await mod.getSessionFields(sessionId);
						return jsonResponse({ fields: fields ?? {} });
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to get session fields" },
							500,
						);
					}
				},
			});

			// PATCH /auth/session/fields — update custom fields on a session
			ctx.addEndpoint({
				method: "PATCH",
				path: "/auth/session/fields",
				metadata: {
					requireAuth: true,
					description: "Update custom fields on a session",
				},
				async handler(request, _endpointCtx) {
					let body: Record<string, unknown>;
					try {
						body = (await request.json()) as Record<string, unknown>;
					} catch {
						return jsonResponse({ error: "Invalid JSON body" }, 400);
					}

					const sessionId = typeof body.sessionId === "string" ? body.sessionId : null;
					if (!sessionId) {
						return jsonResponse({ error: "Missing required field: sessionId" }, 400);
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
						await mod.updateSessionFields(sessionId, fields);
						return jsonResponse({ updated: true });
					} catch (err) {
						const message = err instanceof Error ? err.message : "Update failed";
						const status = message.includes("not found") ? 404 : 500;
						return jsonResponse({ error: message }, status);
					}
				},
			});

			return {
				context: { customSession: mod },
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
