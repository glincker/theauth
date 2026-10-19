/**
 * Per-model database hooks: `before` and `after` for create and update on user, session and account.
 *
 * `before` runs ahead of the write. It can abort (return `false`) or replace part of the payload
 * (return `{ data }`). It fails closed: a throw, a timeout or a malformed result aborts the write,
 * whatever `hookSafety.onError` says. `after` runs once the write has committed. Its errors are
 * logged and swallowed, because the row already exists and cannot be taken back.
 *
 * Hooks never run inside a claim statement (a conditional UPDATE or DELETE that only one caller may
 * win), so they cannot break single-use consumption. Each call site runs `before` ahead of the
 * claim-protected write and `after` behind it.
 */
import { z } from "zod";
import { normalizeEmail } from "../auth/normalize-email.js";
import type { IdSource } from "../db/id-generation.js";
import { createIdSource, defaultIdSource } from "../db/id-generation.js";
import type { TheAuthLogger } from "../observability/types.js";
import { runWithTimeout } from "./run.js";
import type { HookSafetyConfig } from "./safety.js";
import { resolveHookSafety } from "./safety.js";

export type DatabaseHookModel = "user" | "session" | "account";
export type DatabaseHookOperation = "create" | "update";

/** User fields a hook sees. `before` may replace `email`, `name` and `metadata`, never `id`. */
export interface UserHookData {
	id: string;
	email: string;
	name: string | null;
	metadata: Record<string, unknown> | null;
}

/** Session fields a hook sees. `before` may replace `expiresAt` and `metadata`, never `id` or `userId`. */
export interface SessionHookData {
	id: string;
	userId: string;
	expiresAt: Date;
	metadata: Record<string, unknown> | null;
}

/** Linked OAuth account fields a hook sees. Tokens are never exposed. `before` may replace `expiresAt`. */
export interface AccountHookData {
	id: string;
	userId: string;
	provider: string;
	providerAccountId: string;
	expiresAt: Date | null;
}

/** What a `before` hook may replace, per model. Anything else aborts the write. */
export interface DatabaseHookPatch {
	user: Partial<Pick<UserHookData, "email" | "name" | "metadata">>;
	session: Partial<Pick<SessionHookData, "expiresAt" | "metadata">>;
	account: Partial<Pick<AccountHookData, "expiresAt">>;
}

export interface DatabaseHookData {
	user: UserHookData;
	session: SessionHookData;
	account: AccountHookData;
}

export interface DatabaseHookContext {
	operation: DatabaseHookOperation;
	/** Aborted when the hook timeout fires. */
	signal: AbortSignal;
}

/** `false` aborts the write. `{ data }` replaces the listed fields. `undefined` proceeds unchanged. */
export type DatabaseBeforeResult<M extends DatabaseHookModel> =
	| undefined
	// biome-ignore lint/suspicious/noConfusingVoidType: lets an async hook with no return value type check.
	| void
	| false
	| { data: DatabaseHookPatch[M] };

export interface DatabaseModelHooks<M extends DatabaseHookModel> {
	create?: {
		before?: (
			data: DatabaseHookData[M],
			ctx: DatabaseHookContext,
		) => Promise<DatabaseBeforeResult<M>> | DatabaseBeforeResult<M>;
		after?: (row: DatabaseHookData[M], ctx: DatabaseHookContext) => Promise<void> | void;
	};
	update?: {
		before?: (
			data: DatabaseHookData[M],
			ctx: DatabaseHookContext,
		) => Promise<DatabaseBeforeResult<M>> | DatabaseBeforeResult<M>;
		after?: (row: DatabaseHookData[M], ctx: DatabaseHookContext) => Promise<void> | void;
	};
}

/**
 * Per-model database hooks, same shape as Better Auth's `databaseHooks`. On update, `data` is the
 * row as it would be stored after the write (current row plus the change).
 */
export interface DatabaseHooks {
	user?: DatabaseModelHooks<"user">;
	session?: DatabaseModelHooks<"session">;
	account?: DatabaseModelHooks<"account">;
}

export type DatabaseHookErrorCode =
	| "DATABASE_HOOK_ABORTED"
	| "DATABASE_HOOK_FAILED"
	| "DATABASE_HOOK_TIMEOUT"
	| "DATABASE_HOOK_INVALID_PAYLOAD";

/** Thrown when a `before` hook stops a write. The write did not happen. Branch on `code`. */
export class DatabaseHookError extends Error {
	readonly code: DatabaseHookErrorCode;
	readonly model: DatabaseHookModel;
	readonly operation: DatabaseHookOperation;

	constructor(
		code: DatabaseHookErrorCode,
		model: DatabaseHookModel,
		operation: DatabaseHookOperation,
		message: string,
	) {
		super(message);
		this.name = "DatabaseHookError";
		this.code = code;
		this.model = model;
		this.operation = operation;
	}
}

export interface DatabaseHookRunner extends IdSource {
	/** False when no hook is configured, so call sites can skip their extra reads. */
	readonly active: boolean;
	/** True when a `before` or `after` hook exists for this model and operation. */
	has(model: DatabaseHookModel, operation: DatabaseHookOperation): boolean;
	/**
	 * Runs the `before` hook and returns the data to store. Throws DatabaseHookError to abort.
	 */
	before<M extends DatabaseHookModel>(
		model: M,
		operation: DatabaseHookOperation,
		data: DatabaseHookData[M],
	): Promise<DatabaseHookData[M]>;
	/** Runs the `after` hook. Never throws. */
	after<M extends DatabaseHookModel>(
		model: M,
		operation: DatabaseHookOperation,
		row: DatabaseHookData[M],
	): Promise<void>;
}

const metadataSchema = z.record(z.string(), z.unknown()).nullable();
const dateSchema = z.date().refine((d) => !Number.isNaN(d.getTime()), "invalid date");

const patchSchemas = {
	user: z
		.object({
			email: z.string().trim().email().max(320).optional(),
			name: z.string().trim().max(256).nullable().optional(),
			metadata: metadataSchema.optional(),
		})
		.strict(),
	session: z
		.object({ expiresAt: dateSchema.optional(), metadata: metadataSchema.optional() })
		.strict(),
	account: z.object({ expiresAt: dateSchema.nullable().optional() }).strict(),
} as const;

function applyPatch<M extends DatabaseHookModel>(
	model: M,
	data: DatabaseHookData[M],
	patch: unknown,
): DatabaseHookData[M] {
	const parsed = patchSchemas[model].safeParse(patch);
	if (!parsed.success) {
		const detail = parsed.error.issues
			.map((i) => `${i.path.join(".") || "data"}: ${i.message}`)
			.join("; ");
		throw new DatabaseHookError(
			"DATABASE_HOOK_INVALID_PAYLOAD",
			model,
			"create",
			`${model} hook returned an invalid payload: ${detail}`,
		);
	}
	const next: Record<string, unknown> = { ...data };
	for (const [key, value] of Object.entries(parsed.data)) {
		if (value === undefined) continue;
		next[key] = key === "email" && typeof value === "string" ? normalizeEmail(value) : value;
	}
	return next as unknown as DatabaseHookData[M];
}

const NOOP_RUNNER: DatabaseHookRunner = {
	...defaultIdSource(),
	active: false,
	has: () => false,
	before: async (_model, _operation, data) => data,
	after: async () => {},
};

export interface DatabaseHookRunnerOptions {
	logger?: Pick<TheAuthLogger, "warn" | "error">;
	hookSafety?: HookSafetyConfig;
	/** The `advanced.database.generateId` option. Default: random UUIDs. */
	generateId?: unknown;
}

type AnyHook = (data: unknown, ctx: DatabaseHookContext) => unknown;

/** Build the runner for a `databaseHooks` config. Returns a shared no-op runner when it is empty. */
export function createDatabaseHookRunner(
	hooks: DatabaseHooks | undefined,
	options: DatabaseHookRunnerOptions = {},
): DatabaseHookRunner {
	const ids =
		options.generateId === undefined ? defaultIdSource() : createIdSource(options.generateId);
	const withIds = (base: DatabaseHookRunner): DatabaseHookRunner =>
		ids === defaultIdSource() ? base : { ...base, newId: (model) => ids.newId(model) };
	if (!hooks) return withIds(NOOP_RUNNER);
	const configured = (["user", "session", "account"] as const).some((m) => {
		const h = hooks[m];
		return !!(h?.create?.before || h?.create?.after || h?.update?.before || h?.update?.after);
	});
	if (!configured) return withIds(NOOP_RUNNER);

	const timeoutMs = resolveHookSafety({ timeoutMs: options.hookSafety?.timeoutMs })
		.beforeAgentCreate.timeoutMs;

	function pick(
		model: DatabaseHookModel,
		operation: DatabaseHookOperation,
		phase: "before" | "after",
	): AnyHook | undefined {
		const group = (hooks as DatabaseHooks | undefined)?.[model] as
			| Record<string, Record<string, AnyHook | undefined> | undefined>
			| undefined;
		return group?.[operation]?.[phase];
	}

	return {
		newId: (model) => ids.newId(model),
		active: true,
		has: (model, operation) =>
			!!(pick(model, operation, "before") || pick(model, operation, "after")),
		async before(model, operation, data) {
			const hook = pick(model, operation, "before");
			if (!hook) return data;
			const res = await runWithTimeout(
				async (signal) => hook(copyForHook(data), { operation, signal }),
				timeoutMs,
			);
			if (!res.ok) {
				if (res.timedOut) {
					throw new DatabaseHookError(
						"DATABASE_HOOK_TIMEOUT",
						model,
						operation,
						`${model}.${operation}.before hook timed out after ${timeoutMs}ms`,
					);
				}
				options.logger?.error("database hook failed", {
					model,
					operation,
					error: String(res.error),
				});
				throw new DatabaseHookError(
					"DATABASE_HOOK_FAILED",
					model,
					operation,
					`${model}.${operation}.before hook failed`,
				);
			}
			const value = res.value;
			if (value === undefined || value === null) return data;
			if (value === false) {
				throw new DatabaseHookError(
					"DATABASE_HOOK_ABORTED",
					model,
					operation,
					`${model} ${operation} was stopped by a before hook`,
				);
			}
			if (value === true) return data;
			if (typeof value !== "object" || !("data" in value)) {
				throw new DatabaseHookError(
					"DATABASE_HOOK_INVALID_PAYLOAD",
					model,
					operation,
					`${model}.${operation}.before hook returned an unsupported result`,
				);
			}
			try {
				return applyPatch(model, data, (value as { data: unknown }).data);
			} catch (err) {
				if (err instanceof DatabaseHookError) {
					throw new DatabaseHookError(err.code, model, operation, err.message);
				}
				throw err;
			}
		},
		async after(model, operation, row) {
			const hook = pick(model, operation, "after");
			if (!hook) return;
			const res = await runWithTimeout(
				async (signal) => hook(copyForHook(row), { operation, signal }),
				timeoutMs,
			);
			if (!res.ok) {
				options.logger?.warn("database after hook failed", {
					model,
					operation,
					timedOut: res.timedOut,
					error: String(res.error),
				});
			}
		},
	};
}

/** Hand hooks a shallow copy so mutating the argument cannot change what is stored. */
function copyForHook<T>(data: T): T {
	if (typeof data !== "object" || data === null) return data;
	const copy = { ...(data as Record<string, unknown>) };
	for (const [k, v] of Object.entries(copy)) {
		if (v instanceof Date) copy[k] = new Date(v.getTime());
		else if (typeof v === "object" && v !== null) copy[k] = { ...(v as Record<string, unknown>) };
	}
	return copy as T;
}
