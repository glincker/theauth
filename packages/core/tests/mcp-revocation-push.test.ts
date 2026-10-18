/** Revocation push: delegation, agent and session revokes feed the shared denylist through the bus. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAgentModule } from "../src/agent/agent.js";
import { users } from "../src/db/schema.js";
import { createDelegationModule } from "../src/delegation/delegation.js";
import { createRevocationBus } from "../src/mcp/revocation-bus.js";
import type {
	McpRevocationEntry,
	McpRevocationEvent,
	McpRevocationStore,
} from "../src/mcp/revocation-types.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const EXP = new Date(Date.now() + 3_600_000);
const PERMS = [{ resource: "mcp:github:*", actions: ["read"] }];

interface FakeStore extends McpRevocationStore {
	rows: Map<string, McpRevocationEntry>;
	calls: McpRevocationEntry[][];
	failNext: number;
}

function fakeStore(): FakeStore {
	const store: FakeStore = {
		rows: new Map(),
		calls: [],
		failNext: 0,
		async revokeMany(entries) {
			if (store.failNext > 0) {
				store.failNext -= 1;
				throw new Error("store down");
			}
			store.calls.push(entries);
			for (const e of entries) store.rows.set(`${e.kind}:${e.id}`, e);
		},
		async check() {
			return null;
		},
		async fingerprint() {
			return String(store.rows.size);
		},
		async prune() {
			return 0;
		},
		async isRevoked() {
			return false;
		},
		async revoke() {},
	} as unknown as FakeStore;
	return store;
}

describe("revocation push", () => {
	let theauth: TheAuth;
	beforeEach(async () => {
		theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], tokenExpiry: "24h" },
		});
		await theauth.db.insert(users).values({
			id: "user-1",
			email: "u@example.com",
			name: "U",
			createdAt: new Date(),
			updatedAt: new Date(),
		});
	});

	const mk = (name: string, permissions = PERMS) =>
		theauth.agent.create({ ownerId: "user-1", name, type: "delegated", permissions });

	function wire(store?: FakeStore, extra: Parameters<typeof createRevocationBus>[0] = {}) {
		const bus = createRevocationBus({ store, retryDelayMs: 1, ...extra });
		const delegation = createDelegationModule({ db: theauth.db, revocations: bus });
		const agents = createAgentModule({
			db: theauth.db,
			maxPerUser: 10,
			defaultPermissions: [],
			tokenExpiry: "24h",
			revocations: bus,
		});
		return { bus, delegation, agents };
	}

	async function chain3() {
		const a = await mk("a");
		const b = await mk("b", []);
		const c = await mk("c", []);
		const base = { permissions: PERMS, expiresAt: EXP };
		const ab = await theauth.delegate({ fromAgent: a.id, toAgent: b.id, ...base });
		const bc = await theauth.delegate({ fromAgent: b.id, toAgent: c.id, ...base });
		return { a, b, c, ab, bc };
	}

	it("pushes the revoked link and every cascade child", async () => {
		const store = fakeStore();
		const { delegation } = wire(store);
		const { ab, bc } = await chain3();
		const revoked = await delegation.revokeDelegation(ab.id);
		expect(revoked.sort()).toEqual([ab.id, bc.id].sort());
		expect([...store.rows.keys()].sort()).toEqual([`dlg:${ab.id}`, `dlg:${bc.id}`].sort());
		const row = store.rows.get(`dlg:${bc.id}`);
		expect(row?.reason).toBe("delegation.revoke");
		expect(row?.sourceId).toBe(ab.id);
		expect(row?.expiresAt.getTime()).toBeGreaterThanOrEqual(EXP.getTime() - 1000);
	});

	it("carries the root owner and root id on the event", async () => {
		const seen: McpRevocationEvent[] = [];
		const { bus, delegation } = wire(fakeStore());
		bus.subscribe((e) => seen.push(e));
		const { ab, bc } = await chain3();
		await delegation.revokeDelegation(ab.id);
		expect(seen).toHaveLength(1);
		expect(seen[0]).toMatchObject({ kind: "dlg", userId: "user-1", sourceId: ab.id });
		expect(seen[0]?.ids.sort()).toEqual([ab.id, bc.id].sort());
	});

	it("pushes nothing when the link was already revoked", async () => {
		const store = fakeStore();
		const { delegation } = wire(store);
		const { ab } = await chain3();
		await delegation.revokeDelegation(ab.id);
		store.calls.length = 0;
		await delegation.revokeDelegation(ab.id);
		expect(store.calls).toHaveLength(0);
	});

	it("agent revoke pushes the agent and its bound delegations", async () => {
		const store = fakeStore();
		const { agents } = wire(store);
		const { b, ab, bc } = await chain3();
		const result = await agents.revoke(b.id);
		expect(result.revokedDelegations.sort()).toEqual([ab.id, bc.id].sort());
		expect([...store.rows.keys()].sort()).toEqual(
			[`agent:${b.id}`, `dlg:${ab.id}`, `dlg:${bc.id}`].sort(),
		);
		expect(store.rows.get(`agent:${b.id}`)?.reason).toBe("agent.revoke");
	});

	it("is idempotent: revoking again and publishing duplicates never throws", async () => {
		const store = fakeStore();
		const { agents, bus } = wire(store);
		const { b } = await chain3();
		await agents.revoke(b.id);
		const before = store.rows.size;
		await agents.revoke(b.id);
		expect(store.rows.size).toBe(before);
		const entry: McpRevocationEntry = {
			kind: "dlg",
			id: "x",
			expiresAt: EXP,
			reason: "t",
		};
		store.calls.length = 0;
		await bus.publish({ kind: "dlg", ids: ["x"], revokedAt: new Date(), reason: "t" }, [
			entry,
			entry,
			{ ...entry },
		]);
		expect(store.calls[0]).toHaveLength(1);
	});

	it("a store failure does not break the revoke, is retried once and reported", async () => {
		const store = fakeStore();
		store.failNext = 1;
		const onPushFailure = vi.fn();
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const { delegation, bus } = wire(store, { onPushFailure, logger });
		const { ab } = await chain3();

		await expect(delegation.revokeDelegation(ab.id)).resolves.toHaveLength(2);
		expect(store.rows.has(`dlg:${ab.id}`)).toBe(true);
		expect(onPushFailure).not.toHaveBeenCalled();
		expect(bus.stats().retries).toBe(1);
		expect(bus.stats().pushFailures).toBe(0);

		const second = await chain3();
		store.failNext = 2;
		await expect(delegation.revokeDelegation(second.ab.id)).resolves.toHaveLength(2);
		expect(store.rows.has(`dlg:${second.ab.id}`)).toBe(false);
		expect(onPushFailure).toHaveBeenCalledTimes(1);
		expect(onPushFailure.mock.calls[0]?.[0]).toMatchObject({ kind: "dlg", attempts: 2 });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(bus.stats().pushFailures).toBe(1);
		const [row] = await theauth.db.query.delegationChains.findMany({
			where: (t, { eq }) => eq(t.id, second.ab.id),
		});
		expect(row?.status).toBe("revoked");
	});

	it("is a no-op without a store but in-process listeners still fire", async () => {
		const { delegation, bus } = wire(undefined);
		const seen: McpRevocationEvent[] = [];
		const off = bus.subscribe((e) => seen.push(e));
		const { ab } = await chain3();
		await delegation.revokeDelegation(ab.id);
		expect(seen).toHaveLength(1);
		expect(bus.stats().rowsPushed).toBe(0);
		off();
		const next = await chain3();
		await delegation.revokeDelegation(next.ab.id);
		expect(seen).toHaveLength(1);
	});

	it("a throwing listener does not stop the others or the revoke", async () => {
		const { delegation, bus } = wire(fakeStore());
		const ok = vi.fn();
		bus.subscribe(() => {
			throw new Error("boom");
		});
		bus.subscribe(ok);
		const { ab } = await chain3();
		await expect(delegation.revokeDelegation(ab.id)).resolves.toHaveLength(2);
		expect(ok).toHaveBeenCalledTimes(1);
	});

	it("the instance facade publishes on auth.revocations", async () => {
		const seen: McpRevocationEvent[] = [];
		theauth.revocations.subscribe((e) => seen.push(e));
		const { a, ab } = await chain3();
		await theauth.delegation.revoke(ab.id);
		await theauth.agent.revoke(a.id);
		expect(seen.map((e) => e.kind)).toEqual(["dlg", "agent"]);
	});

	it("onRevoked runs after the push without blocking the revoke", async () => {
		const store = fakeStore();
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const onRevoked = vi.fn(() => gate);
		const { delegation } = wire(store, { onRevoked });
		const { ab } = await chain3();
		await delegation.revokeDelegation(ab.id);
		await vi.waitFor(() => expect(onRevoked).toHaveBeenCalledTimes(1));
		release();
	});
});
