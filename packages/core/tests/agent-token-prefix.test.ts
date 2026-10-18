import { eq } from "drizzle-orm";
import { describe, expect, it, vi } from "vitest";
import {
	AGENT_TOKEN_PREFIX,
	agentTokenLookupPrefix,
	isAgentToken,
	LEGACY_AGENT_TOKEN_PREFIXES,
} from "../src/agent/token-format.js";
import { sha256 } from "../src/crypto/web-crypto.js";
import * as schema from "../src/db/schema.js";
import { bearerTokenOf, requireAgent } from "../src/http/require-agent.js";
import { createTheAuth } from "../src/theauth.js";

const PERMS = [{ resource: "tool:read", actions: ["read"] }];

async function setup() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10 },
	});
	auth.db
		.insert(schema.users)
		.values({
			id: "u1",
			email: "u1@x.io",
			name: "u1",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return auth;
}

/** Insert an agent row as an older release would have: kv_ token, known hash. */
async function insertLegacyAgent(auth: Awaited<ReturnType<typeof setup>>, token: string) {
	const now = new Date();
	await auth.db.insert(schema.agents).values({
		id: "legacy-1",
		ownerId: "u1",
		name: "legacy",
		type: "autonomous",
		status: "active",
		tokenHash: await sha256(token),
		tokenPrefix: token.slice(0, 11),
		expiresAt: new Date(now.getTime() + 3_600_000),
		metadata: {},
		createdAt: now,
		updatedAt: now,
	});
	await auth.db.insert(schema.permissions).values({
		id: "legacy-perm",
		agentId: "legacy-1",
		resource: "tool:read",
		actions: ["read"],
		createdAt: now,
	});
}

const LEGACY = `kv_${"A".repeat(42)}A`;

describe("agent token prefix", () => {
	it("isAgentToken accepts ta_ and legacy kv_ only", () => {
		expect(AGENT_TOKEN_PREFIX).toBe("ta_");
		expect(LEGACY_AGENT_TOKEN_PREFIXES).toEqual(["kv_"]);
		expect(isAgentToken("ta_abc")).toBe(true);
		expect(isAgentToken("kv_abc")).toBe(true);
		expect(isAgentToken("xx_abc")).toBe(false);
		expect(isAgentToken("kveph_abc")).toBe(false);
		expect(isAgentToken("")).toBe(false);
		expect(isAgentToken("TA_abc")).toBe(false);
		expect(agentTokenLookupPrefix("ta_12345678rest")).toBe("ta_12345678");
	});

	it("issues ta_ tokens of 46 characters with a ta_ stored prefix", async () => {
		const auth = await setup();
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "a",
			type: "autonomous",
			permissions: PERMS,
		});
		expect(agent.token).toMatch(/^ta_[A-Za-z0-9_-]{43}$/);
		const [row] = await auth.db.select().from(schema.agents).where(eq(schema.agents.id, agent.id));
		expect(row?.tokenPrefix).toBe(agent.token.slice(0, 11));
		expect(row?.tokenPrefix.startsWith("ta_")).toBe(true);
	});

	it("still authorizes a legacy kv_ token by hash", async () => {
		const auth = await setup();
		await insertLegacyAgent(auth, LEGACY);
		const ok = await auth.authorizeByToken(LEGACY, { action: "read", resource: "tool:read" });
		expect(ok.allowed).toBe(true);
		expect((await auth.agent.validateToken(LEGACY))?.id).toBe("legacy-1");
	});

	it("rotate converts a legacy agent to a ta_ token and retires the kv_ one", async () => {
		const auth = await setup();
		await insertLegacyAgent(auth, LEGACY);
		const rotated = await auth.agent.rotate("legacy-1");
		expect(rotated.token.startsWith("ta_")).toBe(true);
		expect(await auth.agent.validateToken(LEGACY)).toBeNull();
		expect((await auth.agent.validateToken(rotated.token))?.id).toBe("legacy-1");
		const [row] = await auth.db
			.select()
			.from(schema.agents)
			.where(eq(schema.agents.id, "legacy-1"));
		expect(row?.tokenPrefix.startsWith("ta_")).toBe(true);
	});

	it("rejects an unknown prefix before any DB lookup", async () => {
		const auth = await setup();
		const select = vi.spyOn(auth.db, "select");
		expect(await auth.agent.validateToken("zz_notours")).toBeNull();
		expect(select).not.toHaveBeenCalled();
		const denied = await auth.authorizeByToken("zz_notours", {
			action: "read",
			resource: "tool:read",
		});
		expect(denied.allowed).toBe(false);
	});

	it("HTTP bearer parsing and requireAgent accept both prefixes", async () => {
		const auth = await setup();
		await insertLegacyAgent(auth, LEGACY);
		const fresh = await auth.agent.create({
			ownerId: "u1",
			name: "n",
			type: "autonomous",
			permissions: PERMS,
		});
		for (const token of [LEGACY, fresh.token]) {
			const req = new Request("http://x.test/", { headers: { Authorization: `Bearer ${token}` } });
			expect(bearerTokenOf(req)).toBe(token);
			const result = await requireAgent(auth, req, { action: "read", resource: "tool:read" });
			expect(result.ok).toBe(true);
		}
	});
});
