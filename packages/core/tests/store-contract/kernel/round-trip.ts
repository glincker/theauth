import { describe, expect, it } from "vitest";
import type { MakeTarget } from "./target.js";
import { uid } from "./target.js";

const SECOND = 1_700_000_000;

/** Every value kind the schema uses must come back as core wrote it. */
export function defineRoundTrip(make: MakeTarget): void {
	describe("value round trip", () => {
		it("returns text, JSON, booleans, dates and large integers exactly", async () => {
			const t = await make();
			const k = t.stores.kernel;
			try {
				const id = uid("rt");
				const metadata = {
					z: 1,
					a: { nested: [1, 2.5, "three", null, true], text: "café 中文 \u{1f600}" },
					empty: "",
					zero: 0,
				};
				const long = "x".repeat(5000);
				await k.insert("users", {
					id,
					email: `${id}@kernel.test`,
					username: null,
					name: long,
					metadata,
					banned: 1,
					emailVerified: 0,
					createdAt: new Date(SECOND * 1000),
					updatedAt: new Date((SECOND + 1) * 1000),
				});
				const row = await k.findOne("users", [{ field: "id", op: "eq", value: id }]);
				expect(row?.name).toBe(long);
				expect(row?.username).toBeNull();
				expect(row?.metadata).toEqual(metadata);
				expect(row?.banned).toBe(1);
				expect(row?.emailVerified).toBe(0);
				expect(row?.forcePasswordReset).toBe(0); // schema default
				expect((row?.createdAt as Date).getTime()).toBe(SECOND * 1000);
				expect((row?.updatedAt as Date).getTime()).toBe((SECOND + 1) * 1000);
			} finally {
				await t.close();
			}
		});

		it("keeps an empty string distinct from null, and integers past 32 bits", async () => {
			const t = await make();
			const k = t.stores.kernel;
			try {
				const id = uid("rt");
				const now = new Date(SECOND * 1000);
				await k.insert("users", {
					id,
					email: `${id}@kernel.test`,
					name: "",
					metadata: null,
					createdAt: now,
					updatedAt: now,
				});
				const row = await k.findOne("users", [{ field: "id", op: "eq", value: id }]);
				expect(row?.name).toBe("");
				expect(row?.metadata).toBeNull();
				const owner = id;
				const farFuture = 4_102_444_800; // year 2100, past 2^31
				const enr = uid("enr");
				await k.insert("deviceEnrollments", {
					id: enr,
					kind: "claim",
					tokenHash: uid("h"),
					ownerId: owner,
					maxUses: 7,
					uses: 0,
					expiresAt: farFuture,
					createdAt: SECOND,
					template: { groups: [], permissions: [] },
				});
				const back = await k.findOne("deviceEnrollments", [{ field: "id", op: "eq", value: enr }]);
				expect(back?.expiresAt).toBe(farFuture);
				expect(back?.maxUses).toBe(7);
				expect(back?.template).toEqual({ groups: [], permissions: [] });
			} finally {
				await t.close();
			}
		});

		it("applies schema defaults for columns the row leaves out", async () => {
			const t = await make();
			const k = t.stores.kernel;
			try {
				const id = uid("rt");
				const now = new Date(SECOND * 1000);
				await k.insert("users", {
					id,
					email: `${id}@kernel.test`,
					name: null,
					metadata: null,
					createdAt: now,
					updatedAt: now,
				});
				const owner = id;
				const agentId = uid("a");
				await k.insert("agents", {
					id: agentId,
					ownerId: owner,
					name: "n",
					type: "service",
					tokenHash: "h",
					tokenPrefix: "p",
					createdAt: now,
					updatedAt: now,
				});
				const agent = await k.findOne("agents", [{ field: "id", op: "eq", value: agentId }]);
				expect(agent?.status).toBe("active");
				expect(agent?.expiresAt).toBeNull();
				expect(agent?.cnf).toBeNull();
			} finally {
				await t.close();
			}
		});
	});
}
