/**
 * Runs the quorum vote path against a real Prisma client on SQLite. It is skipped unless
 * THEAUTH_PRISMA_REAL_DIR points at a directory where `prisma`, `@prisma/client` and
 * `@prisma/adapter-better-sqlite3` (Prisma 7) are installed and the client was generated from
 * `src/schema.prisma` with the sqlite provider and the schema pushed to `test.db`.
 */
import { createRequire } from "node:module";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { createPrismaAdapter } from "../src/adapter.js";
import type { TheAuthPrismaAdapter } from "../src/types.js";
import { ApprovalVoteError } from "../src/types.js";

const dir = process.env.THEAUTH_PRISMA_REAL_DIR;

interface RealClient {
	theAuthApprovalRequest: {
		create(a: { data: unknown }): Promise<unknown>;
		findUnique(a: {
			where: { id: string };
		}): Promise<{ status: string; respondedBy: string | null } | null>;
		deleteMany(a?: unknown): Promise<unknown>;
	};
	theAuthApprovalVote: { deleteMany(a?: unknown): Promise<unknown> };
}

describe.skipIf(!dir)("prisma adapter quorum votes on a real SQLite client", () => {
	let prisma: RealClient;
	let db: TheAuthPrismaAdapter;

	beforeAll(async () => {
		const req = createRequire(join(dir as string, "x.js"));
		const { PrismaClient } = req("@prisma/client");
		const { PrismaBetterSqlite3 } = req("@prisma/adapter-better-sqlite3");
		prisma = new PrismaClient({
			adapter: new PrismaBetterSqlite3({ url: `file:${join(dir as string, "test.db")}` }),
		});
		db = createPrismaAdapter(prisma as never);
		await prisma.theAuthApprovalVote.deleteMany({});
		await prisma.theAuthApprovalRequest.deleteMany({});
	});

	async function seed(id: string, required: number | null, expiresInMs = 60_000) {
		await prisma.theAuthApprovalRequest.create({
			data: {
				id,
				agentId: "agent-1",
				userId: "requester",
				action: "deploy",
				resource: "prod",
				status: "pending",
				expiresAt: new Date(Date.now() + expiresInMs),
				createdAt: new Date(),
				requiredApprovals: required,
			},
		});
	}

	it("counts distinct approvers and flips to approved at the quorum", async () => {
		await seed("q1", 2);
		const a = await db.castApprovalVote({ approvalId: "q1", approverId: "alice", now: new Date() });
		expect(a).toEqual({ kind: "pending", approvers: ["alice"] });
		const b = await db.castApprovalVote({ approvalId: "q1", approverId: "bob", now: new Date() });
		expect(b.kind).toBe("approved");
		expect((await prisma.theAuthApprovalRequest.findUnique({ where: { id: "q1" } }))?.status).toBe(
			"approved",
		);
	});

	it("treats a null quorum as one approver", async () => {
		await seed("q-null", null);
		const r = await db.castApprovalVote({
			approvalId: "q-null",
			approverId: "alice",
			now: new Date(),
		});
		expect(r.kind).toBe("approved");
	});

	it("refuses the requester and a repeat approver", async () => {
		await seed("q2", 3);
		await expect(
			db.castApprovalVote({ approvalId: "q2", approverId: "requester", now: new Date() }),
		).rejects.toMatchObject({ code: "SELF_APPROVAL" });
		await db.castApprovalVote({ approvalId: "q2", approverId: "alice", now: new Date() });
		await expect(
			db.castApprovalVote({ approvalId: "q2", approverId: "alice", now: new Date() }),
		).rejects.toBeInstanceOf(ApprovalVoteError);
		expect(await db.listApprovalVotes("q2")).toHaveLength(1);
	});

	it("counts one vote when the same approver votes twice at once", async () => {
		await seed("q3", 3);
		const results = await Promise.allSettled(
			Array.from({ length: 6 }, () =>
				db.castApprovalVote({ approvalId: "q3", approverId: "alice", now: new Date() }),
			),
		);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
		expect(await db.listApprovalVotes("q3")).toHaveLength(1);
	});

	it("lets exactly one concurrent caller complete the quorum", async () => {
		await seed("q4", 2);
		const names = ["a", "b", "c", "d", "e", "f"];
		const results = await Promise.all(
			names.map((n) => db.castApprovalVote({ approvalId: "q4", approverId: n, now: new Date() })),
		);
		const approved = results.filter((r) => r.kind === "approved");
		expect(approved.length).toBeGreaterThanOrEqual(1);
		const row = await prisma.theAuthApprovalRequest.findUnique({ where: { id: "q4" } });
		expect(row?.status).toBe("approved");
		// Every approved result names only approvers inside the first quorum.
		const winners = new Set(approved.flatMap((r) => (r.kind === "approved" ? r.approvers : [])));
		expect(winners.size).toBe(2);
		expect(winners.has(row?.respondedBy ?? "")).toBe(true);
	});

	it("withdraws the vote when the request already expired", async () => {
		await seed("q5", 2, -1000);
		const r = await db.castApprovalVote({ approvalId: "q5", approverId: "alice", now: new Date() });
		expect(r).toEqual({ kind: "lost" });
		expect(await db.listApprovalVotes("q5")).toHaveLength(0);
	});

	it("reports NOT_FOUND for an unknown request", async () => {
		await expect(
			db.castApprovalVote({ approvalId: "nope", approverId: "alice", now: new Date() }),
		).rejects.toMatchObject({ code: "NOT_FOUND" });
	});
});
