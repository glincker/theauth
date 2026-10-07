import { agents, auditLogs, delegationChains } from "@glinr/theauth";
import { describe, expect, it } from "vitest";
import { initTheAuth } from "../src/init.js";

describe("initTheAuth (gateway CLI database init)", () => {
	it("creates the agent tables on a fresh database", async () => {
		const theauth = await initTheAuth(":memory:");

		// Each query throws "no such table" if the table was never created.
		await expect(theauth.db.select().from(agents)).resolves.toEqual([]);
		await expect(theauth.db.select().from(auditLogs)).resolves.toEqual([]);
		await expect(theauth.db.select().from(delegationChains)).resolves.toEqual([]);
	});

	it("allows the first agent call on a fresh database", async () => {
		const theauth = await initTheAuth(":memory:");

		await expect(theauth.agent.list({ ownerId: "user-1" })).resolves.toEqual([]);
	});
});
