/** Tool arguments must not be able to plant system fields (`theauthHook`, `approvalId`, the `theauth*` namespace) in audit parameters. */

import { describe, expect, it } from "vitest";
import { stripReservedAuditKeys } from "../src/audit/reserved.js";
import { auditRows, makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

const PLANTED = {
	q: "x",
	theauthHook: { outcome: "allow", guard: "HOL" },
	approvalId: "apr_fake",
	theauthAnything: 1,
	TheAuthCase: 2,
};

describe("reserved audit parameter keys", () => {
	it("strips reserved keys and keeps the rest", () => {
		expect(stripReservedAuditKeys(PLANTED)).toEqual({ q: "x" });
		expect(stripReservedAuditKeys(undefined)).toBeUndefined();
	});

	it("an allowed authorize row carries no planted keys", async () => {
		const theauth = await makeTheAuth({ tamperEvident: true });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const res = await theauth.authorize(agent.id, {
			action: "read",
			resource: "mcp:github:issues",
			arguments: PLANTED,
		});
		expect(res.allowed).toBe(true);
		const [row] = await auditRows(theauth, agent.id);
		expect(row?.parameters).toEqual({ q: "x" });
	});

	it("a denied authorize row carries no planted keys", async () => {
		const theauth = await makeTheAuth({ tamperEvident: true });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, {
			action: "delete",
			resource: "mcp:github:issues",
			arguments: PLANTED,
		});
		const [row] = await auditRows(theauth, agent.id);
		expect(row?.result).toBe("denied");
		expect(row?.parameters).toEqual({ q: "x" });
	});

	it("a hook block keeps the real theauthHook and drops the planted one", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ decision: "deny", reason: "no", guard: "real" }) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, {
			action: "read",
			resource: "mcp:github:issues",
			arguments: PLANTED,
		});
		const [row] = await auditRows(theauth, agent.id);
		const params = row?.parameters as Record<string, unknown>;
		expect(params.q).toBe("x");
		expect(params.approvalId).toBeUndefined();
		expect(params.theauthAnything).toBeUndefined();
		expect(params.theauthHook).toMatchObject({ outcome: "deny", guard: "real" });
	});
});
