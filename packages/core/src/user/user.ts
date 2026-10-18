import { eq } from "drizzle-orm";
import { z } from "zod";
import { isErasedId } from "../audit/pseudonym.js";
import { normalizeEmail } from "../auth/normalize-email.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import { toStoreConflict } from "../db/store-conflict.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";

/** A row of `theauth_users`. */
export type UserRow = typeof users.$inferSelect;

export interface CreateUserInput {
	email: string;
	name?: string;
	/** Use your auth provider's user id here so agent ownerId matches it. Generated when omitted. */
	id?: string;
	metadata?: Record<string, unknown>;
}

export type UserErrorCode = "USER_INVALID_INPUT" | "USER_ID_CONFLICT" | "USER_EMAIL_CONFLICT";

/** Thrown by `user.create()`. Branch on `code`. */
export class UserError extends Error {
	readonly code: UserErrorCode;

	constructor(code: UserErrorCode, message: string) {
		super(message);
		this.name = "UserError";
		this.code = code;
	}
}

export interface UserModule {
	/** Create a user, or return the existing one for the same email. Throws UserError. */
	create(input: CreateUserInput): Promise<UserRow>;
	/** Look up by id first, then by normalized email. Returns null when neither matches. */
	get(idOrEmail: string): Promise<UserRow | null>;
}

const createUserSchema = z.object({
	email: z.string().trim().email().max(320).transform(normalizeEmail),
	name: z.string().trim().max(256).optional(),
	id: z
		.string()
		.trim()
		.min(1)
		.max(191)
		.refine((v) => !isErasedId(v), { message: "ids starting with [deleted- are reserved" })
		.optional(),
	metadata: z.record(z.string(), z.unknown()).optional(),
});

/** Create the user module: idempotent create and lookup by id or email. */
export function createUserModule(config: {
	db: Database;
	databaseHooks?: DatabaseHookRunner;
}): UserModule {
	const { db } = config;
	const databaseHooks = config.databaseHooks ?? createDatabaseHookRunner(undefined);

	async function findById(id: string): Promise<UserRow | null> {
		const rows = await db.select().from(users).where(eq(users.id, id));
		return rows[0] ?? null;
	}

	async function findByEmail(email: string): Promise<UserRow | null> {
		const rows = await db.select().from(users).where(eq(users.email, email));
		return rows[0] ?? null;
	}

	async function get(idOrEmail: string): Promise<UserRow | null> {
		const byId = await findById(idOrEmail);
		if (byId) return byId;
		return findByEmail(normalizeEmail(idOrEmail));
	}

	/**
	 * Applies the idempotency rules for an email and an optional requested id.
	 * Returns the row to reuse, or null when nothing matches yet. Throws on a conflict.
	 */
	async function matchExisting(email: string, id: string | undefined): Promise<UserRow | null> {
		const byEmail = await findByEmail(email);
		if (byEmail) {
			if (id === undefined || byEmail.id === id) return byEmail;
			throw new UserError(
				"USER_EMAIL_CONFLICT",
				`Email ${email} is already registered under a different user id than "${id}".`,
			);
		}
		if (id !== undefined && (await findById(id))) {
			throw new UserError(
				"USER_ID_CONFLICT",
				`User id "${id}" is already in use by another email.`,
			);
		}
		return null;
	}

	/**
	 * Creates a user, or returns the existing row when the email is already taken.
	 * The email is validated and lowercased. An `id` is generated when omitted.
	 * Existing rows are never updated: a repeat call returns the row as it was first stored.
	 */
	async function create(input: CreateUserInput): Promise<UserRow> {
		const parsed = createUserSchema.safeParse(input);
		if (!parsed.success) {
			const detail = parsed.error.issues
				.map((issue) => `${issue.path.join(".") || "input"}: ${issue.message}`)
				.join("; ");
			throw new UserError("USER_INVALID_INPUT", `Invalid user input: ${detail}`);
		}
		const { id, metadata } = parsed.data;
		let { email, name } = parsed.data;

		const existing = await matchExisting(email, id);
		if (existing) return existing;

		const newId = id ?? generateId();
		let storedMetadata: Record<string, unknown> | null = metadata ?? null;
		let storedName: string | null = name ? name : null;
		if (databaseHooks.has("user", "create")) {
			const hooked = await databaseHooks.before("user", "create", {
				id: newId,
				email,
				name: storedName,
				metadata: storedMetadata,
			});
			storedName = hooked.name ? hooked.name : null;
			storedMetadata = hooked.metadata;
			if (hooked.email !== email) {
				email = hooked.email;
				// A replaced email follows the same idempotency rules as a requested one.
				const again = await matchExisting(email, id);
				if (again) return again;
			}
		}
		name = storedName ?? undefined;

		const now = new Date();
		try {
			await db.insert(users).values({
				id: newId,
				email,
				name: storedName,
				metadata: storedMetadata,
				createdAt: now,
				updatedAt: now,
			});
		} catch (err) {
			if (!toStoreConflict(err, "users")) throw err;
			// A concurrent create won the race. Re-read and apply the same rules.
			const raced = await matchExisting(email, id);
			if (raced) return raced;
			throw err;
		}

		const created = await findByEmail(email);
		if (!created) throw new Error(`User row for ${email} was not readable after insert.`);
		await databaseHooks.after("user", "create", {
			id: created.id,
			email: created.email,
			name: created.name ?? null,
			metadata: created.metadata ?? null,
		});
		return created;
	}

	return { create, get };
}
