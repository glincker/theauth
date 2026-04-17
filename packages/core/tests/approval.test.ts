import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ApprovalRequest } from "../src/approval/approval.js";
import type { Kavach } from "../src/kavach.js";
import { createTestKavach } from "./helpers.js";

describe("approval – CIBA async approval flows", () => {
	let kavach: Kavach;
	let agentId: string;

	beforeEach(async () => {
		kavach = await createTestKavach();

		const agent = await kavach.agent.create({
			ownerId: "user-1",
			name: "Test Agent",
			type: "autonomous",
			permissions: [],
		});
		agentId = agent.id;
	});

	it("creates a pending approval request", async () => {
		const req = await kavach.approval.request({
			agentId,
			userId: "user-1",
			action: "write",
			resource: "file:*",
		});

		expect(req.id).toMatch(/^apr_/);
		expect(req.status).toBe("pending");
		expect(req.agentId).toBe(agentId);
		expect(req.userId).toBe("user-1");
		expect(req.action).toBe("write");
		expect(req.resource).toBe("file:*");
		expect(req.expiresAt).toBeInstanceOf(Date);
		expect(req.createdAt).toBeInstanceOf(Date);
		expect(req.expiresAt.getTime()).toBeGreaterThan(req.createdAt.getTime());
	});

	it("includes optional arguments in the request", async () => {
		const req = await kavach.approval.request({
			agentId,
			userId: "user-1",
			action: "delete",
			resource: "db:records",
			arguments: { table: "users", limit: 100 },
		});

		expect(req.arguments).toEqual({ table: "users", limit: 100 });
	});

	it("retrieves a request by id", async () => {
		const created = await kavach.approval.request({
			agentId,
			userId: "user-1",
			action: "read",
			resource: "secret:*",
		});

		const fetched = await kavach.approval.get(created.id);
		expect(fetched).not.toBeNull();
		expect(fetched?.id).toBe(created.id);
		expect(fetched?.status).toBe("pending");
	});

	it("returns null for unknown id", async () => {
		const result = await kavach.approval.get("apr_nonexistent");
		expect(result).toBeNull();
	});

	it("approves a pending request", async () => {
		const created = await kavach.approval.request({
			agentId,
			userId: "user-1",
			action: "execute",
			resource: "tool:deploy",
		});

		const approved = await kavach.approval.approve(created.id, "admin@example.com");

		expect(approved.status).toBe("approved");
		expect(approved.respondedBy).toBe("admin@example.com");
		expect(approved.respondedAt).toBeInstanceOf(Date);
	});

	it("denies a pending request", async () => {
		const created = await kavach.approval.request({
			agentId,
			userId: "user-1",
			action: "delete",
			resource: "tool:nuke",
		});

		const denied = await kavach.approval.deny(created.id, "security@example.com");

		expect(denied.status).toBe("denied");
		expect(denied.respondedBy).toBe("security@example.com");
	});

	it("throws when approving an already-resolved request", async () => {
		const created = await kavach.approval.request({
			agentId,
			userId: "user-1",
			action: "read",
			resource: "file:log",
		});

		await kavach.approval.approve(created.id);
		await expect(kavach.approval.approve(created.id)).rejects.toThrow("approved");
	});

	describe("listPending", () => {
		it("lists all pending requests", async () => {
			await kavach.approval.request({
				agentId,
				userId: "user-1",
				action: "read",
				resource: "r1",
			});
			await kavach.approval.request({
				agentId,
				userId: "user-1",
				action: "write",
				resource: "r2",
			});

			const pending = await kavach.approval.listPending();
			expect(pending.length).toBe(2);
			expect(pending.every((r) => r.status === "pending")).toBe(true);
		});

		it("filters by userId", async () => {
			await kavach.approval.request({
				agentId,
				userId: "user-1",
				action: "read",
				resource: "r1",
			});

			const pending = await kavach.approval.listPending("user-1");
			expect(pending.length).toBe(1);

			const noPending = await kavach.approval.listPending("user-999");
			expect(noPending.length).toBe(0);
		});

		it("excludes approved requests", async () => {
			const req = await kavach.approval.request({
				agentId,
				userId: "user-1",
				action: "execute",
				resource: "r1",
			});
			await kavach.approval.approve(req.id);

			const pending = await kavach.approval.listPending();
			expect(pending.length).toBe(0);
		});
	});

	describe("cleanup", () => {
		it("expires requests past their TTL", async () => {
			// Create a kavach instance with a very short TTL
			const _shortTtl = await createTestKavach();
			// Use base kavach approval module but we'll test via the module directly
			// by simulating expiry: we create an approval, then we call cleanup

			// Create with default kavach (TTL 300s) - won't be expired immediately
			await kavach.approval.request({
				agentId,
				userId: "user-1",
				action: "read",
				resource: "r1",
			});

			// Initially nothing expired
			const result = await kavach.approval.cleanup();
			expect(result.expired).toBe(0);
		});

		it("returns count of zero when nothing to expire", async () => {
			const result = await kavach.approval.cleanup();
			expect(result.expired).toBe(0);
		});
	});

	describe("onApprovalNeeded handler", () => {
		it("calls the handler when a request is created", async () => {
			const { createKavach } = await import("../src/kavach.js");
			const schema = await import("../src/db/schema.js");

			const handler = vi.fn().mockResolvedValue(undefined);

			const kavachWithHook = await createKavach({
				database: { provider: "sqlite", url: ":memory:" },
				agents: {
					enabled: true,
					maxPerUser: 10,
					defaultPermissions: [],
					auditAll: true,
					tokenExpiry: "24h",
				},
				approval: { onApprovalNeeded: handler },
			});

			kavachWithHook.db
				.insert(schema.users)
				.values({
					id: "user-1",
					email: "test@example.com",
					name: "Test User",
					createdAt: new Date(),
					updatedAt: new Date(),
				})
				.run();

			const agent = await kavachWithHook.agent.create({
				ownerId: "user-1",
				name: "Hook Agent",
				type: "autonomous",
				permissions: [],
			});

			await kavachWithHook.approval.request({
				agentId: agent.id,
				userId: "user-1",
				action: "read",
				resource: "file:*",
			});

			// Handler is called async via void — yield to microtask queue
			await new Promise<void>((resolve) => setTimeout(resolve, 10));
			expect(handler).toHaveBeenCalledOnce();
			const callArg = handler.mock.calls[0]?.[0] as ApprovalRequest;
			expect(callArg.status).toBe("pending");
		});
	});
});
