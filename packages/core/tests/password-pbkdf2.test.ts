/** PBKDF2 parameters: 600000 default, env and config override, legacy verify, rehash on sign-in. */

import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createUsernameAuthModule } from "../src/auth/username.js";
import {
	DEFAULT_PBKDF2_ITERATIONS,
	pbkdf2Hash,
	pbkdf2NeedsRehash,
	pbkdf2Verify,
	resolvePbkdf2Iterations,
} from "../src/crypto/web-crypto.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { usernameAccounts } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const iterationsOf = (h: string) => Number(h.split(":")[1]);

async function setup(pbkdf2Iterations?: number) {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const sessions = createSessionManager({ secret: SECRET }, db);
	const mod = createUsernameAuthModule(
		pbkdf2Iterations === undefined ? {} : { pbkdf2Iterations },
		db,
		sessions,
	);
	const stored = async () =>
		(await db.select().from(usernameAccounts).where(eq(usernameAccounts.username, "alice")))[0]
			?.passwordHash as string;
	return { db, mod, stored };
}

describe("iteration configuration", () => {
	afterEach(() => vi.unstubAllEnvs());

	it("defaults to 600000", () => {
		vi.stubEnv("THEAUTH_PBKDF2_ITERATIONS", "");
		expect(DEFAULT_PBKDF2_ITERATIONS).toBe(600_000);
		expect(resolvePbkdf2Iterations()).toBe(600_000);
	});

	it("reads THEAUTH_PBKDF2_ITERATIONS, config wins over env", () => {
		vi.stubEnv("THEAUTH_PBKDF2_ITERATIONS", "1234");
		expect(resolvePbkdf2Iterations()).toBe(1234);
		expect(resolvePbkdf2Iterations(99)).toBe(99);
	});

	it("rejects invalid values", () => {
		vi.stubEnv("THEAUTH_PBKDF2_ITERATIONS", "abc");
		expect(() => resolvePbkdf2Iterations()).toThrow(/THEAUTH_PBKDF2_ITERATIONS/);
		expect(() => resolvePbkdf2Iterations(0)).toThrow(/pbkdf2Iterations/);
	});

	it("stores iterations and algorithm with each hash", async () => {
		vi.stubEnv("THEAUTH_PBKDF2_ITERATIONS", "2000");
		const h = await pbkdf2Hash("pw");
		expect(h.startsWith("pbkdf2:2000:")).toBe(true);
		expect(await pbkdf2Verify("pw", h)).toBe(true);
	});
});

describe("verify and rehash", () => {
	afterEach(() => vi.unstubAllEnvs());

	it("verifies legacy hashes with their stored parameters", async () => {
		const legacy = await pbkdf2Hash("pw", undefined, 100_000);
		expect(await pbkdf2Verify("pw", legacy)).toBe(true);
		expect(await pbkdf2Verify("nope", legacy)).toBe(false);
		expect(pbkdf2NeedsRehash(legacy, 600_000)).toBe(true);
		expect(pbkdf2NeedsRehash(legacy, 100_000)).toBe(false);
		expect(pbkdf2NeedsRehash("garbage", 1000)).toBe(true);
	});

	it("rejects malformed stored hashes", async () => {
		expect(await pbkdf2Verify("pw", "pbkdf2:abc:00:00")).toBe(false);
		expect(await pbkdf2Verify("pw", "pbkdf2:0:00:00")).toBe(false);
		expect(await pbkdf2Verify("pw", "bcrypt:1:2:3")).toBe(false);
	});

	it("upgrades a low-iteration hash on successful sign-in", async () => {
		const { db, mod, stored } = await setup(3000);
		await mod.signUp({ username: "alice", password: "Password1!" });
		const low = await pbkdf2Hash("Password1!", undefined, 500);
		await db.update(usernameAccounts).set({ passwordHash: low });
		expect(iterationsOf(await stored())).toBe(500);

		await mod.signIn({ username: "alice", password: "Password1!" });
		const upgraded = await stored();
		expect(iterationsOf(upgraded)).toBe(3000);
		expect(await pbkdf2Verify("Password1!", upgraded)).toBe(true);
	});

	it("does not rehash on a wrong password or when already at target", async () => {
		const { db, mod, stored } = await setup(3000);
		await mod.signUp({ username: "alice", password: "Password1!" });
		const low = await pbkdf2Hash("Password1!", undefined, 500);
		await db.update(usernameAccounts).set({ passwordHash: low });
		await expect(mod.signIn({ username: "alice", password: "Wrong1234!" })).rejects.toThrow();
		expect(await stored()).toBe(low);

		await mod.signIn({ username: "alice", password: "Password1!" });
		const first = await stored();
		await mod.signIn({ username: "alice", password: "Password1!" });
		expect(await stored()).toBe(first);
	});

	it("picks up a parameter bump from env at module creation", async () => {
		vi.stubEnv("THEAUTH_PBKDF2_ITERATIONS", "4000");
		const { db, mod, stored } = await setup();
		await mod.signUp({ username: "alice", password: "Password1!" });
		expect(iterationsOf(await stored())).toBe(4000);
		await db
			.update(usernameAccounts)
			.set({ passwordHash: await pbkdf2Hash("Password1!", undefined, 1000) });
		await mod.signIn({ username: "alice", password: "Password1!" });
		expect(iterationsOf(await stored())).toBe(4000);
	});
});

describe("timing shape", () => {
	it("unknown user and wrong password both pay a hash and fail identically", async () => {
		const iterations = 100_000;
		const { mod } = await setup(iterations);
		await mod.signUp({ username: "alice", password: "Password1!" });
		const median = (xs: number[]) =>
			[...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] as number;
		const time = async (username: string) => {
			const t = performance.now();
			await expect(mod.signIn({ username, password: "Wrong1234!" })).rejects.toThrow(
				"Invalid username or password",
			);
			return performance.now() - t;
		};
		await time("nobody");
		const unknown: number[] = [];
		const wrong: number[] = [];
		for (let i = 0; i < 5; i++) {
			unknown.push(await time("nobody"));
			wrong.push(await time("alice"));
		}
		const ratio = median(unknown) / median(wrong);
		expect(ratio).toBeGreaterThan(0.4);
		expect(ratio).toBeLessThan(2.5);
	});
});
