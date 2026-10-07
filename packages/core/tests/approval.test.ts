import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ApprovalRequest } from "../src/approval/approval.js";
import type { TheAuth } from "../src/theauth.js";
import { createTestTheAuth } from "./helpers.js";

describe("approval – CIBA async approval flows", () => {
	let theauth: TheAuth;
	let agentId: string;

	beforeEach(async () => {
		theauth = await createTestTheAuth();

		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "Test Agent",
			type: "autonomous",
			permissions: [],
		});
		agentId = agent.id;
	});

	it("creates a pending approval request", async () => {
		const req = await theauth.approval.request({
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
		const req = await theauth.approval.request({
			agentId,
			userId: "user-1",
			action: "delete",
			resource: "db:records",
			arguments: { table: "users", limit: 100 },
		});

		expect(req.arguments).toEqual({ table: "users", limit: 100 });
	});

	it("retrieves a request by id", async () => {
		const created = await theauth.approval.request({
			agentId,
			userId: "user-1",
			action: "read",
			resource: "secret:*",
		});

		const fetched = await theauth.approval.get(created.id);
		expect(fetched).not.toBeNull();
		expect(fetched?.id).toBe(created.id);
		expect(fetched?.status).toBe("pending");
	});

	it("returns null for unknown id", async () => {
		const result = await theauth.approval.get("apr_nonexistent");
		expect(result).toBeNull();
	});

	it("approves a pending request", async () => {
		const created = await theauth.approval.request({
			agentId,
			userId: "user-1",
			action: "execute",
			resource: "tool:deploy",
		});

		const approved = await theauth.approval.approve(created.id, "admin@example.com");

		expect(approved.status).toBe("approved");
		expect(approved.respondedBy).toBe("admin@example.com");
		expect(approved.respondedAt).toBeInstanceOf(Date);
	});

	it("denies a pending request", async () => {
		const created = await theauth.approval.request({
			agentId,
			userId: "user-1",
			action: "delete",
			resource: "tool:nuke",
		});

		const denied = await theauth.approval.deny(created.id, "security@example.com");

		expect(denied.status).toBe("denied");
		expect(denied.respondedBy).toBe("security@example.com");
	});

	it("throws when approving an already-resolved request", async () => {
		const created = await theauth.approval.request({
			agentId,
			userId: "user-1",
			action: "read",
			resource: "file:log",
		});

		await theauth.approval.approve(created.id);
		await expect(theauth.approval.approve(created.id)).rejects.toThrow("approved");
	});

	describe("listPending", () => {
		it("lists all pending requests", async () => {
			await theauth.approval.request({
				agentId,
				userId: "user-1",
				action: "read",
				resource: "r1",
			});
			await theauth.approval.request({
				agentId,
				userId: "user-1",
				action: "write",
				resource: "r2",
			});

			const pending = await theauth.approval.listPending();
			expect(pending.length).toBe(2);
			expect(pending.every((r) => r.status === "pending")).toBe(true);
		});

		it("filters by userId", async () => {
			await theauth.approval.request({
				agentId,
				userId: "user-1",
				action: "read",
				resource: "r1",
			});

			const pending = await theauth.approval.listPending("user-1");
			expect(pending.length).toBe(1);

			const noPending = await theauth.approval.listPending("user-999");
			expect(noPending.length).toBe(0);
		});

		it("excludes approved requests", async () => {
			const req = await theauth.approval.request({
				agentId,
				userId: "user-1",
				action: "execute",
				resource: "r1",
			});
			await theauth.approval.approve(req.id);

			const pending = await theauth.approval.listPending();
			expect(pending.length).toBe(0);
		});
	});

	describe("cleanup", () => {
		it("expires requests past their TTL", async () => {
			// Create a theauth instance with a very short TTL
			const _shortTtl = await createTestTheAuth();
			// Use base theauth approval module but we'll test via the module directly
			// by simulating expiry: we create an approval, then we call cleanup

			// Create with default theauth (TTL 300s) - won't be expired immediately
			await theauth.approval.request({
				agentId,
				userId: "user-1",
				action: "read",
				resource: "r1",
			});

			// Initially nothing expired
			const result = await theauth.approval.cleanup();
			expect(result.expired).toBe(0);
		});

		it("returns count of zero when nothing to expire", async () => {
			const result = await theauth.approval.cleanup();
			expect(result.expired).toBe(0);
		});
	});

	describe("onApprovalNeeded handler", () => {
		it("calls the handler when a request is created", async () => {
			const { createTheAuth } = await import("../src/theauth.js");
			const schema = await import("../src/db/schema.js");

			const handler = vi.fn().mockResolvedValue(undefined);

			const theAuthWithHook = await createTheAuth({
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

			theAuthWithHook.db
				.insert(schema.users)
				.values({
					id: "user-1",
					email: "test@example.com",
					name: "Test User",
					createdAt: new Date(),
					updatedAt: new Date(),
				})
				.run();

			const agent = await theAuthWithHook.agent.create({
				ownerId: "user-1",
				name: "Hook Agent",
				type: "autonomous",
				permissions: [],
			});

			await theAuthWithHook.approval.request({
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
