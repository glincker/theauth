import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { afterAll, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { runMigrations } from "../src/db/migrate/index.js";
import type { SingleUseStores, StoreKernel } from "../src/db/store/index.js";
import { createDrizzleKernel, createSingleUseStores } from "../src/db/store/index.js";
import { withQueryLatency } from "./store-contract/latency.js";

const dir = mkdtempSync(join(tmpdir(), "theauth-single-use-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const PARALLEL = 24;
let seq = 0;
const id = (tag: string) => `${tag}-${++seq}`;
const future = () => new Date(Date.now() + 3_600_000);
const past = () => new Date(Date.now() - 3_600_000);

async function open(): Promise<{ kernel: StoreKernel; repos: SingleUseStores }> {
	// Every query yields first, so a read-then-write claim has a window to lose in.
	const sqlite = new BetterSqlite3(join(dir, `s${++seq}.db`));
	sqlite.pragma("journal_mode = WAL");
	sqlite.pragma("busy_timeout = 5000");
	sqlite.pragma("foreign_keys = ON");
	const db = withQueryLatency(drizzle(sqlite)) as unknown as Database;
	await runMigrations(db, "sqlite");
	const kernel = createDrizzleKernel(db, "sqlite");
	return { kernel, repos: createSingleUseStores(kernel) };
}

const wins = (results: boolean[]) => results.filter(Boolean).length;
const race = (fn: () => Promise<boolean>) => Promise.all(Array.from({ length: PARALLEL }, fn));

describe("single-use repositories on the Drizzle kernel", () => {
	it("marks a magic link used once, and refuses an expired or used one", async () => {
		const { kernel, repos } = await open();
		const row = {
			id: id("ml"),
			email: "a@s.test",
			token: "tok-1",
			used: false,
			createdAt: new Date(),
		};
		await kernel.insert("magicLinks", { ...row, expiresAt: future() });
		expect(wins(await race(() => repos.magicLinks.markUsed("tok-1", new Date())))).toBe(1);
		expect(await repos.magicLinks.markUsed("tok-1", new Date())).toBe(false);
		await kernel.insert("magicLinks", { ...row, id: id("ml"), token: "tok-2", expiresAt: past() });
		expect(await repos.magicLinks.markUsed("tok-2", new Date())).toBe(false);
	});

	it("spends exactly max OTP guesses and deletes once", async () => {
		const { kernel, repos } = await open();
		const otpId = id("otp");
		await kernel.insert("emailOtps", {
			id: otpId,
			email: "o@s.test",
			codeHash: "h",
			expiresAt: future(),
			attempts: 0,
			createdAt: new Date(),
		});
		expect(wins(await race(() => repos.emailOtps.reserveAttempt(otpId, 5)))).toBe(5);
		expect(wins(await race(() => repos.emailOtps.consume(otpId)))).toBe(1);
	});

	it("flips one-time token, jwt refresh, oidc code and oidc refresh rows once", async () => {
		const { kernel, repos } = await open();
		const user = id("u");
		await kernel.insert("users", {
			id: user,
			email: `${user}@s.test`,
			name: null,
			metadata: null,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const ott = id("ott");
		await kernel.insert("oneTimeTokens", {
			id: ott,
			tokenHash: id("h"),
			identifier: "i",
			purpose: "p",
			used: false,
			expiresAt: future(),
			createdAt: new Date(),
		});
		expect(wins(await race(() => repos.oneTimeTokens.markUsed(ott)))).toBe(1);
		const jwt = id("jwt");
		await kernel.insert("jwtRefreshTokens", {
			id: jwt,
			userId: user,
			tokenHash: id("h"),
			used: false,
			expiresAt: future(),
			createdAt: new Date(),
		});
		expect(wins(await race(() => repos.jwtRefreshTokens.markUsed(jwt)))).toBe(1);
	});

	it("deletes a session for one caller only", async () => {
		const { kernel, repos } = await open();
		const user = id("u");
		await kernel.insert("users", {
			id: user,
			email: `${user}@s.test`,
			name: null,
			metadata: null,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const sid = id("sess");
		await kernel.insert("sessions", {
			id: sid,
			userId: user,
			tokenHash: id("h"),
			expiresAt: future(),
			createdAt: new Date(),
		});
		expect(wins(await race(() => repos.sessions.deleteOnce(sid)))).toBe(1);
	});

	it("claims a refresh token from 0 once and spends an enrollment use up to its cap", async () => {
		const { kernel, repos } = await open();
		const user = id("u");
		await kernel.insert("users", {
			id: user,
			email: `${user}@s.test`,
			name: null,
			metadata: null,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const family = id("fam");
		await kernel.insert("refreshTokenFamilies", {
			id: family,
			userId: user,
			revoked: 0,
			absoluteExpiresAt: future(),
			createdAt: new Date(),
		});
		await kernel.insert("refreshTokens", {
			id: id("rt"),
			familyId: family,
			tokenHash: "hash-1",
			used: 0,
			expiresAt: future(),
			createdAt: new Date(),
		});
		expect(wins(await race(() => repos.refreshTokens.claim("hash-1", 100)))).toBe(1);
		expect(await repos.refreshTokens.claim("hash-1", 200)).toBe(false);

		const nowSec = Math.floor(Date.now() / 1000);
		const enr = id("enr");
		await kernel.insert("deviceEnrollments", {
			id: enr,
			kind: "claim",
			tokenHash: id("h"),
			ownerId: user,
			maxUses: 3,
			uses: 0,
			expiresAt: nowSec + 3600,
			createdAt: nowSec,
			template: { groups: [], permissions: [] },
		});
		expect(wins(await race(() => repos.deviceEnrollments.spendUse(enr, nowSec)))).toBe(3);
		expect(wins(await race(() => repos.deviceEnrollments.revoke(enr, nowSec)))).toBe(1);
		expect(await repos.deviceEnrollments.spendUse(enr, nowSec)).toBe(false);
	});
});

describe("kernel ltField filter", () => {
	it("compares one column with another on the same row", async () => {
		const { kernel } = await open();
		const owner = id("u");
		await kernel.insert("users", {
			id: owner,
			email: `${owner}@s.test`,
			name: null,
			metadata: null,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const nowSec = Math.floor(Date.now() / 1000);
		const mk = (uses: number) => ({
			id: id("enr"),
			kind: "claim",
			tokenHash: id("h"),
			ownerId: owner,
			maxUses: 2,
			uses,
			expiresAt: nowSec + 3600,
			createdAt: nowSec,
			template: { groups: [], permissions: [] },
		});
		const open1 = mk(1);
		await kernel.insert("deviceEnrollments", open1);
		await kernel.insert("deviceEnrollments", mk(2));
		const rows = await kernel.findMany("deviceEnrollments", {
			where: [{ field: "uses", op: "ltField", other: "maxUses" }],
		});
		expect(rows.map((r) => r.id)).toEqual([open1.id]);
	});
});
