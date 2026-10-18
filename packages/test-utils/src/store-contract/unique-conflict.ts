import { describe, expect, it } from "vitest";
import { uniqueEmail } from "./claim-races.js";
import type { StoreContractTarget } from "./types.js";

type Make = () => Promise<StoreContractTarget>;

/** A unique index is the arbiter in a few places. The backend must reject duplicates, and say so in a way core recognizes. */
export function defineUniqueConflict(make: Make, parallel: number): void {
	describe("unique conflict", () => {
		it("creates one user for parallel creates of the same email", async () => {
			const t = await make();
			try {
				const email = uniqueEmail("dup");
				const settled = await Promise.allSettled(
					Array.from({ length: parallel }, () => t.auth.user.create({ email })),
				);
				// create is idempotent on email: every caller gets the same row, none sees the constraint error.
				const failed = settled.filter((s) => s.status === "rejected");
				expect(failed).toHaveLength(0);
				const ids = new Set(settled.flatMap((s) => (s.status === "fulfilled" ? [s.value.id] : [])));
				expect(ids.size).toBe(1);
			} finally {
				await t.close();
			}
		});

		it("reports a duplicate key as a typed conflict", async () => {
			const t = await make();
			try {
				if (!t.duplicateInsert) return; // optional capability
				expect(await t.duplicateInsert()).toBe("typed");
			} finally {
				await t.close();
			}
		});
	});
}
