import { eq } from "drizzle-orm";
import { z } from "zod";
import { normalizeEmail } from "../auth/normalize-email.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";

/** A row of `theauth_users`. */
export type UserRow = typeof users.$inferSelect;

const createUserSchema = z.object({
	email: z.string().trim().email().transform(normalizeEmail),
	name: z.string().optional(),
	id: z.string().min(1).optional(),
});

/** Input for `user.create()`. */
export type CreateUserInput = z.input<typeof createUserSchema>;

/** Create the user module: idempotent create and lookup by id or email. */
export function createUserModule(config: { db: Database }) {
	const { db } = config;

	async function findByEmail(email: string): Promise<UserRow | null> {
		const rows = await db.select().from(users).where(eq(users.email, email));
		return rows[0] ?? null;
	}

	async function get(idOrEmail: string): Promise<UserRow | null> {
		const byId = await db.select().from(users).where(eq(users.id, idOrEmail));
		if (byId[0]) return byId[0];
		return findByEmail(normalizeEmail(idOrEmail));
	}

	/**
	 * Creates a user, or returns the existing row when the email is already taken.
	 * The email is validated and lowercased. An `id` is generated when omitted.
	 */
	async function create(input: CreateUserInput): Promise<UserRow> {
		const { email, name, id } = createUserSchema.parse(input);

		const existing = await findByEmail(email);
		if (existing) return existing;

		const now = new Date();
		// onConflictDoNothing keeps a concurrent create on the same email from throwing.
		await db
			.insert(users)
			.values({ id: id ?? generateId(), email, name: name ?? null, createdAt: now, updatedAt: now })
			.onConflictDoNothing({ target: users.email });

		const created = await findByEmail(email);
		if (!created) {
			throw new Error(`User id "${id}" is already in use by another email.`);
		}
		return created;
	}

	return { create, get };
}

export type UserModule = ReturnType<typeof createUserModule>;
