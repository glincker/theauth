/**
 * Call-site helpers for `databaseHooks.user.update`.
 *
 * `before` sees the row as it would be stored (current row plus the change) and may replace
 * `email`, `name` and `metadata`. `after` sees the stored row. Neither runs inside a claim
 * statement: callers run `before`, then their own write, then `after`.
 */
import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import type { TheAuthConfig } from "../types.js";
import type { DatabaseHookRunner, UserHookData } from "./database-hooks.js";
import { createDatabaseHookRunner } from "./database-hooks.js";

/** The user columns a hook can see and replace. */
export interface UserFieldChange {
	email?: string;
	name?: string | null;
	metadata?: Record<string, unknown> | null;
}

/** Build the runner for a plugin from the instance config. Same wiring as `createTheAuth`. */
export function databaseHooksFromConfig(
	config: Pick<TheAuthConfig, "databaseHooks" | "hookSafety" | "advanced" | "logger">,
): DatabaseHookRunner {
	return createDatabaseHookRunner(config.databaseHooks, {
		logger: config.logger,
		hookSafety: config.hookSafety,
		generateId: config.advanced?.database?.generateId,
	});
}

function toHookData(row: {
	id: string;
	email: string;
	name: string | null;
	metadata: Record<string, unknown> | null;
}): UserHookData {
	return { id: row.id, email: row.email, name: row.name ?? null, metadata: row.metadata ?? null };
}

async function readUser(db: Database, userId: string): Promise<UserHookData | null> {
	const rows = await db.select().from(users).where(eq(users.id, userId));
	return rows[0] ? toHookData(rows[0]) : null;
}

const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

/**
 * Runs `user.update.before`. Returns the column changes the caller must merge into its own
 * `.set(...)`: the fields the caller already changes (hook-adjusted) plus any field the hook
 * replaced. Throws DatabaseHookError to abort. Returns `change` untouched when no update hook
 * exists or the user row is gone.
 */
export async function beforeUserUpdate(
	runner: DatabaseHookRunner,
	db: Database,
	userId: string,
	change: UserFieldChange = {},
): Promise<UserFieldChange> {
	if (!runner.has("user", "update")) return change;
	const current = await readUser(db, userId);
	if (!current) return change;
	const proposed: UserHookData = { ...current, ...change } as UserHookData;
	const hooked = await runner.before("user", "update", proposed);
	const out: UserFieldChange = {};
	if ("email" in change || hooked.email !== proposed.email) out.email = hooked.email;
	if ("name" in change || hooked.name !== proposed.name) out.name = hooked.name;
	if ("metadata" in change || !same(hooked.metadata, proposed.metadata)) {
		out.metadata = hooked.metadata;
	}
	return out;
}

/** Runs `user.update.after` with the stored row. Never throws. */
export async function afterUserUpdate(
	runner: DatabaseHookRunner,
	db: Database,
	userId: string,
): Promise<void> {
	if (!runner.has("user", "update")) return;
	try {
		const row = await readUser(db, userId);
		if (row) await runner.after("user", "update", row);
	} catch {
		// The write is committed. A failed re-read must not turn it into an error.
	}
}

/** before, the caller's write, after. `write` gets the field changes to merge into its update. */
export async function withUserUpdate(
	runner: DatabaseHookRunner,
	db: Database,
	userId: string,
	change: UserFieldChange,
	write: (effective: UserFieldChange) => Promise<void>,
): Promise<void> {
	const effective = await beforeUserUpdate(runner, db, userId, change);
	await write(effective);
	await afterUserUpdate(runner, db, userId);
}
