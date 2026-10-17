import { beforeEach, describe, expect, it } from "vitest";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import { UserError } from "../src/user/user.js";

/** Resolves to the UserError code thrown by `promise`, or undefined when it resolves or throws another error. */
async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
	try {
		await promise;
		return undefined;
	} catch (err) {
		return err instanceof UserError ? err.code : undefined;
	}
}

describe("user module", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true },
		});
	});

	it("creates a user with a generated id and timestamps", async () => {
		const user = await theauth.user.create({ email: "a@example.com", name: "A" });
		expect(user.id).toBeTruthy();
		expect(user.email).toBe("a@example.com");
		expect(user.name).toBe("A");
		expect(user.createdAt).toBeInstanceOf(Date);
		expect(user.updatedAt).toBeInstanceOf(Date);
	});

	it("honors a supplied id and lowercases the email", async () => {
		const user = await theauth.user.create({ id: "user-123", email: "  Owner@Example.COM " });
		expect(user.id).toBe("user-123");
		expect(user.email).toBe("owner@example.com");
		expect(user.name).toBeNull();
	});

	it("is idempotent on email", async () => {
		const first = await theauth.user.create({ email: "dup@example.com", name: "First" });
		const second = await theauth.user.create({ email: "DUP@example.com", name: "Second" });
		expect(second.id).toBe(first.id);
		expect(second.name).toBe("First");
	});

	it("rejects an invalid email with USER_INVALID_INPUT", async () => {
		const error = await theauth.user.create({ email: "not-an-email" }).catch((err: unknown) => err);
		expect(error).toBeInstanceOf(UserError);
		expect((error as UserError).code).toBe("USER_INVALID_INPUT");
		expect((error as UserError).message).toContain("email");
	});

	it("rejects an over-long name with USER_INVALID_INPUT", async () => {
		const code = await codeOf(
			theauth.user.create({ email: "long@example.com", name: "x".repeat(257) }),
		);
		expect(code).toBe("USER_INVALID_INPUT");
	});

	it("gets by id or email, and returns null when missing", async () => {
		const user = await theauth.user.create({ id: "u1", email: "g@example.com" });
		expect((await theauth.user.get("u1"))?.id).toBe(user.id);
		expect((await theauth.user.get("G@Example.com"))?.id).toBe(user.id);
		expect(await theauth.user.get("missing")).toBeNull();
	});

	it("lets agents use a created user as owner", async () => {
		const owner = await theauth.user.create({ email: "o@example.com" });
		const agent = await theauth.agent.create({
			ownerId: owner.id,
			name: "bot",
			type: "autonomous",
			permissions: [],
		});
		expect(agent.ownerId).toBe(owner.id);
	});

	it("rejects the same email with a different id as USER_EMAIL_CONFLICT", async () => {
		await theauth.user.create({ id: "owner-a", email: "same@example.com" });
		const code = await codeOf(theauth.user.create({ id: "owner-b", email: "same@example.com" }));
		expect(code).toBe("USER_EMAIL_CONFLICT");
		expect(await theauth.user.get("owner-b")).toBeNull();
	});

	it("rejects a new email with an existing id as USER_ID_CONFLICT", async () => {
		await theauth.user.create({ id: "shared-id", email: "first@example.com" });
		const code = await codeOf(
			theauth.user.create({ id: "shared-id", email: "second@example.com" }),
		);
		expect(code).toBe("USER_ID_CONFLICT");
		expect(await theauth.user.get("second@example.com")).toBeNull();
	});

	it("returns the same row for concurrent creates of one email", async () => {
		const rows = await Promise.all([
			theauth.user.create({ email: "race@example.com", name: "One" }),
			theauth.user.create({ email: "race@example.com", name: "Two" }),
			theauth.user.create({ email: "RACE@example.com", name: "Three" }),
		]);
		const ids = new Set(rows.map((row) => row.id));
		expect(ids.size).toBe(1);
		expect(rows.every((row) => row.email === "race@example.com")).toBe(true);
	});

	it("round-trips metadata", async () => {
		const metadata = { plan: "pro", seats: 3, flags: ["beta"] };
		const user = await theauth.user.create({ email: "meta@example.com", metadata });
		expect(user.metadata).toEqual(metadata);
		expect((await theauth.user.get("meta@example.com"))?.metadata).toEqual(metadata);
	});

	it("returns the row unchanged for the same email and id", async () => {
		const first = await theauth.user.create({
			id: "same",
			email: "again@example.com",
			name: "Kept",
		});
		const second = await theauth.user.create({
			id: "same",
			email: "again@example.com",
			name: "Ignored",
			metadata: { changed: true },
		});
		expect(second.id).toBe(first.id);
		expect(second.name).toBe("Kept");
		expect(second.metadata).toBeNull();
	});
});
