/** An agent past its expiresAt is denied on every authorization path, with an audit row. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const PERMS = [{ resource: "mcp:github:*", actions: ["read"] }];
const REQ = { action: "read", resource: "mcp:github:repos" };

async function setup(): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], tokenExpiry: "24h" },
		audit: { tamperEvident: true, hmacKey: "expiry-test-key" },
	});
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "u@example.com",
			name: "U",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return theauth;
}

describe("agent expiry", () => {
	let theauth: TheAuth;
	beforeEach(async () => {
		theauth = await setup();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	const create = (expiresAt: Date) =>
		theauth.agent.create({
			ownerId: "user-1",
			name: "a",
			type: "autonomous",
			permissions: PERMS,
			expiresAt,
		});

	it("authorize() denies an agent created already expired and writes an audit row", async () => {
		const agent = await create(new Date(Date.now() - 1000));
		const result = await theauth.authorize(agent.id, REQ);
		expect(result.allowed).toBe(false);
		expect(result.code).toBe("agent_expired");
		expect(result.auditId).not.toBe("");
		const rows = await theauth.audit.query({ agentId: agent.id, codes: ["agent_expired"] });
		expect(rows).toHaveLength(1);
	});

	it("authorize() denies once the clock passes expiresAt (fake timers)", async () => {
		const agent = await create(new Date(Date.now() + 60_000));
		expect((await theauth.authorize(agent.id, REQ)).allowed).toBe(true);
		vi.useFakeTimers({ now: Date.now() + 120_000 });
		const result = await theauth.authorize(agent.id, REQ);
		expect(result.allowed).toBe(false);
		expect(result.code).toBe("agent_expired");
	});

	it("authorizeByToken() and validateToken() deny an expired agent", async () => {
		const agent = await create(new Date(Date.now() + 60_000));
		vi.useFakeTimers({ now: Date.now() + 120_000 });
		const result = await theauth.authorizeByToken(agent.token, REQ);
		expect(result.allowed).toBe(false);
		expect(result.auditId).not.toBe("");
		expect(await theauth.agent.validateToken(agent.token)).toBeNull();
	});

	it("validateToken() rejects a token whose agent row is still active but elapsed", async () => {
		const agent = await create(new Date(Date.now() - 1000));
		expect(await theauth.agent.validateToken(agent.token)).toBeNull();
	});

	it("an unexpired agent still passes", async () => {
		const agent = await create(new Date(Date.now() + 60_000));
		expect((await theauth.authorize(agent.id, REQ)).allowed).toBe(true);
		expect((await theauth.authorizeByToken(agent.token, REQ)).allowed).toBe(true);
	});

	it("an expired delegator stops lending permissions down the chain", async () => {
		const a = await create(new Date(Date.now() + 60_000));
		const b = await theauth.agent.create({
			ownerId: "user-1",
			name: "b",
			type: "autonomous",
			permissions: [],
		});
		await theauth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: PERMS,
			expiresAt: new Date(Date.now() + 3_600_000),
		});
		expect((await theauth.authorize(b.id, REQ)).allowed).toBe(true);
		vi.useFakeTimers({ now: Date.now() + 120_000 });
		expect((await theauth.authorize(b.id, REQ)).allowed).toBe(false);
		// Revoked and suspended-style statuses are covered in delegation-liveness.test.ts.
	});

	it("an expired delegation link is ignored", async () => {
		const a = await create(new Date(Date.now() + 3_600_000));
		const b = await theauth.agent.create({
			ownerId: "user-1",
			name: "b",
			type: "autonomous",
			permissions: [],
		});
		await theauth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: PERMS,
			expiresAt: new Date(Date.now() + 60_000),
		});
		vi.useFakeTimers({ now: Date.now() + 120_000 });
		expect((await theauth.authorize(b.id, REQ)).allowed).toBe(false);
	});
});

describe("agent expiry boundary", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("denies at the exact expiresAt instant", async () => {
		const theauth = await setup();
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "edge",
			type: "autonomous",
			permissions: PERMS,
			expiresAt: new Date("2030-01-01T00:00:10Z"),
		});
		expect((await theauth.authorize(agent.id, REQ)).allowed).toBe(true);
		vi.setSystemTime(new Date("2030-01-01T00:00:10Z"));
		const result = await theauth.authorize(agent.id, REQ);
		expect(result.allowed).toBe(false);
		expect(result.code).toBe("agent_expired");
	});
});
