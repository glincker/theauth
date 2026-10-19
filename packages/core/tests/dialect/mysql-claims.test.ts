import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDatabase } from "../../src/db/database.js";
import { createExecutor } from "../../src/db/migrate/executor.js";
import { createTokenFamilyStore } from "../../src/session/token-family.js";
import { closeDatabase, createCoreBooter } from "./core-boot.js";

/**
 * MySQL has no RETURNING and counts changed rows, so every claim statement (`claimCount`) depends on the
 * affected row count the driver reports. These tests fire N parallel requests at one row and require exactly one winner.
 * Skipped unless THEAUTH_TEST_MYSQL_URL is set. They run in their own scratch database, so they never touch the dialect suite's tables.
 */
const url = process.env.THEAUTH_TEST_MYSQL_URL;
const SCRATCH = "theauth_w9_claims";
const PARALLEL = 12;
const HOUR = 3_600_000;

function scratchUrl(base: string): string {
	const u = new URL(base);
	u.pathname = `/${SCRATCH}`;
	return u.toString();
}

async function withAdmin(base: string, sql: string): Promise<void> {
	const db = await createDatabase({ provider: "mysql", url: base, experimental: true });
	try {
		await createExecutor(db, "mysql").run(sql);
	} finally {
		await closeDatabase(db);
	}
}

describe.skipIf(!url)("mysql claim statements under concurrency", { timeout: 120_000 }, () => {
	// describe.skipIf still runs this body while collecting, so only build the URL when there is one.
	const booter = createCoreBooter("mysql", url ? scratchUrl(url) : "mysql://unused/unused");

	beforeAll(async () => {
		await withAdmin(url as string, `DROP DATABASE IF EXISTS ${SCRATCH}`);
		await withAdmin(
			url as string,
			`CREATE DATABASE ${SCRATCH} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`,
		);
	}, 60_000);

	afterAll(async () => {
		await booter.closeAll();
		await withAdmin(url as string, `DROP DATABASE IF EXISTS ${SCRATCH}`);
	}, 60_000);

	it("redeems one magic link once across parallel verifies", async () => {
		const { auth, mail } = await booter.boot();
		const magicLink = auth.magicLink;
		if (!magicLink) throw new Error("magicLink module missing");
		await magicLink.sendLink("claim-ml@example.com");
		const token = mail.magicTokens.at(-1) ?? "";
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => magicLink.verify(token)),
		);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		expect(await magicLink.verify(token)).toBeNull();
	});

	it("accepts one email OTP once across parallel verifies", async () => {
		const { auth, mail } = await booter.boot();
		const emailOtp = auth.emailOtp;
		if (!emailOtp) throw new Error("emailOtp module missing");
		await emailOtp.sendCode("claim-otp@example.com");
		const code = mail.otpCodes.at(-1) ?? "";
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => emailOtp.verifyCode("claim-otp@example.com", code)),
		);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		expect(await emailOtp.verifyCode("claim-otp@example.com", code)).toBeNull();
	});

	it("counts every parallel wrong OTP guess, so the attempt limit holds", async () => {
		const { auth, mail } = await booter.boot();
		const emailOtp = auth.emailOtp;
		if (!emailOtp) throw new Error("emailOtp module missing");
		await emailOtp.sendCode("claim-guess@example.com");
		const code = mail.otpCodes.at(-1) ?? "";
		const wrong = code === "000000" ? "111111" : "000000";
		await Promise.all(
			Array.from({ length: 30 }, () => emailOtp.verifyCode("claim-guess@example.com", wrong)),
		);
		// The default limit is far below 30, so the real code no longer works once the guesses are spent.
		expect(await emailOtp.verifyCode("claim-guess@example.com", code)).toBeNull();
	});

	it("lets exactly one parallel approve or deny decide an approval", async () => {
		const { auth } = await booter.boot();
		const user = await auth.user.create({ email: "claim-apr@example.com" });
		const agent = await auth.agent.create({
			ownerId: user.id,
			name: "claim-apr",
			type: "autonomous",
			permissions: [
				{ resource: "mcp:pay:*", actions: ["execute"], constraints: { requireApproval: true } },
			],
		});
		const req = await auth.approval.request({
			agentId: agent.id,
			userId: user.id,
			action: "execute",
			resource: "mcp:pay:refund",
		});
		const settled = await Promise.allSettled(
			Array.from({ length: PARALLEL }, (_, i) =>
				i % 2 === 0 ? auth.approval.approve(req.id, `h${i}`) : auth.approval.deny(req.id, `h${i}`),
			),
		);
		expect(settled.filter((s) => s.status === "fulfilled")).toHaveLength(1);
		const decided = await auth.approval.get(req.id);
		expect(["approved", "denied"]).toContain(decided?.status);
	});

	it("consumes an approved approval once across parallel authorize calls", async () => {
		const { auth } = await booter.boot();
		const user = await auth.user.create({ email: "claim-use@example.com" });
		const agent = await auth.agent.create({
			ownerId: user.id,
			name: "claim-use",
			type: "autonomous",
			permissions: [
				{ resource: "mcp:pay:*", actions: ["execute"], constraints: { requireApproval: true } },
			],
		});
		const req = await auth.approval.request({
			agentId: agent.id,
			userId: user.id,
			action: "execute",
			resource: "mcp:pay:refund",
		});
		await auth.approval.approve(req.id, "human-1");
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () =>
				auth.authorize(agent.id, {
					action: "execute",
					resource: "mcp:pay:refund",
					approvalId: req.id,
				}),
			),
		);
		expect(results.filter((r) => r.allowed)).toHaveLength(1);
	});

	it("rotates one refresh token once across parallel consumes, then revokes the family", async () => {
		const { auth } = await booter.boot();
		const user = await auth.user.create({ email: "claim-rt@example.com" });
		const store = createTokenFamilyStore(auth.db, { reuseGraceMs: 0 });
		const family = await store.createFamily(user.id, new Date(Date.now() + 24 * HOUR));
		const token = await store.issueToken(family.id, HOUR);
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => store.consumeToken(token.rawToken)),
		);
		const statuses = results.map((r) => r.status);
		expect(statuses.filter((s) => s === "ok")).toHaveLength(1);
		// Every loser looks like replay, which revokes the family. Late arrivals may see it already revoked.
		for (const s of statuses.filter((x) => x !== "ok")) expect(["reuse", "revoked"]).toContain(s);
	});
});
