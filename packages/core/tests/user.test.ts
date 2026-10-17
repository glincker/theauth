import { beforeEach, describe, expect, it } from "vitest";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

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

	it("rejects an invalid email", async () => {
		await expect(theauth.user.create({ email: "not-an-email" })).rejects.toThrow();
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
});
