import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import type { TheAuthFastifyOptions } from "../src/adapter.js";
import { theAuthFastify } from "../src/adapter.js";

const ALLOWED_IP = "203.0.113.5";

async function setup(options: Partial<TheAuthFastifyOptions> = {}) {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
	const now = new Date();
	await theauth.db.insert(users).values({
		id: "owner",
		email: "owner@test.com",
		name: "owner",
		createdAt: now,
		updatedAt: now,
	});
	const agent = await theauth.agent.create({
		ownerId: "owner",
		name: "ip-bound",
		type: "autonomous",
		permissions: [
			{ resource: "docs", actions: ["read"], constraints: { ipAllowlist: [ALLOWED_IP] } },
		],
	});
	const app = Fastify();
	await app.register(
		theAuthFastify(theauth, { authenticate: async () => ({ id: "admin" }), ...options }),
	);

	const viaToken = async (headers: Record<string, string>) => {
		const res = await app.inject({
			method: "POST",
			url: "/authorize/token",
			headers: { authorization: `Bearer ${agent.token}`, ...headers },
			payload: { action: "read", resource: "docs" },
		});
		return res.statusCode;
	};
	const viaAgentId = async (headers: Record<string, string>) => {
		const res = await app.inject({
			method: "POST",
			url: "/authorize",
			headers,
			payload: { agentId: agent.id, action: "read", resource: "docs" },
		});
		return res.statusCode;
	};
	return { app, viaToken, viaAgentId };
}

describe("fastify adapter client ip", () => {
	it("denies an ipAllowlist agent when forwarded headers are spoofed (default)", async () => {
		const { app, viaToken, viaAgentId } = await setup();
		const spoof = { "x-forwarded-for": ALLOWED_IP, "x-real-ip": ALLOWED_IP };
		expect(await viaToken(spoof)).toBe(403);
		expect(await viaAgentId(spoof)).toBe(403);
		await app.close();
	});

	it("honors the right-most entry with trustedProxyCount and ignores a spoofed first entry", async () => {
		const { app, viaToken } = await setup({ trustedProxy: { trustedProxyCount: 1 } });
		expect(await viaToken({ "x-forwarded-for": `9.9.9.9, ${ALLOWED_IP}` })).toBe(200);
		expect(await viaToken({ "x-forwarded-for": `${ALLOWED_IP}, 9.9.9.9` })).toBe(403);
		await app.close();
	});

	it("honors a single trustedHeader and ignores x-forwarded-for", async () => {
		const { app, viaToken } = await setup({ trustedProxy: { trustedHeader: "cf-connecting-ip" } });
		expect(await viaToken({ "cf-connecting-ip": ALLOWED_IP })).toBe(200);
		expect(await viaToken({ "cf-connecting-ip": "9.9.9.9", "x-forwarded-for": ALLOWED_IP })).toBe(
			403,
		);
		await app.close();
	});
});
