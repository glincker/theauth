import { describe, expect, it, vi } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createPolicyEngine } from "../src/policy/engine.js";
import { POLICY_ERROR_CODES } from "../src/policy/types.js";
import { createTheAuth } from "../src/theauth.js";

describe("policy.evaluate with an unknown agent", () => {
	it("denies with AGENT_NOT_FOUND when the row is missing and no ownerId is given", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "ghost" },
			action: "read",
			resource: "mcp:api",
		});
		expect(decision.effect).toBe("deny");
		expect(decision.reason).toBe(POLICY_ERROR_CODES.AGENT_NOT_FOUND);
	});
});

describe("authorize hooks", () => {
	it("does not leak unhandled rejections from throwing hooks", async () => {
		const unhandled = vi.fn();
		process.on("unhandledRejection", unhandled);
		try {
			const theauth = await createTheAuth({
				database: { provider: "sqlite", url: ":memory:" },
				agents: {
					enabled: true,
					maxPerUser: 10,
					defaultPermissions: [],
					auditAll: true,
					tokenExpiry: "24h",
				},
				hooks: {
					afterAuthorize: async () => {
						throw new Error("after boom");
					},
					onViolation: () => {
						throw new Error("violation boom");
					},
				},
			});
			const result = await theauth.authorize("missing-agent", {
				action: "read",
				resource: "mcp:x",
			});
			expect(result.allowed).toBe(false);
			await new Promise((r) => setTimeout(r, 20));
			expect(unhandled).not.toHaveBeenCalled();
		} finally {
			process.off("unhandledRejection", unhandled);
		}
	});
});
