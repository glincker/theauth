import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { BASE, makeAuth, newAgent, sessionToken } from "./helpers.js";

async function setup() {
	const auth = await makeAuth();
	const handler = createTheAuthHandler(auth, { rateLimit: false });
	await newAgent(auth, "u1", "a1");
	await newAgent(auth, "u2", "a2");
	const token = await sessionToken(auth, "u1");
	const get = (path: string) =>
		handler(new Request(`${BASE}${path}`, { headers: { authorization: `Bearer ${token}` } }));
	return { get };
}

describe("owner filters are refused, not silently ignored", () => {
	it("audit export with a foreign userId is 403", async () => {
		const { get } = await setup();
		const res = await get("/audit/export?userId=u2");
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: { code: string; message: string } };
		expect(body.error.code).toBe("FORBIDDEN");
		expect(typeof body.error.message).toBe("string");
	});

	it("audit export with the caller's own userId or none is 200", async () => {
		const { get } = await setup();
		expect((await get("/audit/export?userId=u1")).status).toBe(200);
		expect((await get("/audit/export")).status).toBe(200);
	});

	it("audit query and agents list refuse a foreign userId", async () => {
		const { get } = await setup();
		expect((await get("/audit?userId=u2")).status).toBe(403);
		expect((await get("/agents?userId=u2")).status).toBe(403);
		expect((await get("/dashboard/audit?userId=u2")).status).toBe(403);
		expect((await get("/dashboard/agents?userId=u2")).status).toBe(403);
		expect((await get("/agents?userId=u1")).status).toBe(200);
	});
});
