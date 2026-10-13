/**
 * Tests for session freshness enforcement.
 */

import { describe, expect, it } from "vitest";
import { createSessionFreshnessModule } from "../src/session/freshness.js";
import type { Session } from "../src/session/session.js";

function makeSession(createdAgoMs: number): Session {
	const createdAt = new Date(Date.now() - createdAgoMs);
	return {
		id: "test-session-id",
		userId: "test-user-id",
		createdAt,
		expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
	};
}

describe("SessionFreshnessModule", () => {
	describe("isFresh", () => {
		it("returns true for session created 1 second ago", () => {
			const freshness = createSessionFreshnessModule({ freshAge: 300 });
			const session = makeSession(1_000); // 1 second ago
			expect(freshness.isFresh(session)).toBe(true);
		});

		it("returns false for session created 10 minutes ago with 5-minute window", () => {
			const freshness = createSessionFreshnessModule({ freshAge: 300 });
			const session = makeSession(600_000); // 10 minutes ago
			expect(freshness.isFresh(session)).toBe(false);
		});

		it("uses default 5-minute window when not configured", () => {
			const freshness = createSessionFreshnessModule();
			const session = makeSession(200_000); // 3.3 minutes ago
			expect(freshness.isFresh(session)).toBe(true);
		});

		it("respects custom freshAge", () => {
			const freshness = createSessionFreshnessModule({ freshAge: 60 }); // 1 minute
			const session = makeSession(90_000); // 1.5 minutes ago
			expect(freshness.isFresh(session)).toBe(false);
		});
	});

	describe("requireFresh", () => {
		it("returns success for fresh session", () => {
			const freshness = createSessionFreshnessModule({ freshAge: 300 });
			const session = makeSession(1_000);
			const result = freshness.requireFresh(session);

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.freshUntil).toBeInstanceOf(Date);
			}
		});

		it("returns error for stale session", () => {
			const freshness = createSessionFreshnessModule({ freshAge: 300 });
			const session = makeSession(600_000);
			const result = freshness.requireFresh(session);

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("SESSION_NOT_FRESH");
				expect(result.error.details).toBeDefined();
				expect(result.error.details!.freshAge).toBe(300);
			}
		});
	});

	describe("guard", () => {
		it("returns null for fresh session (pass-through)", () => {
			const freshness = createSessionFreshnessModule({ freshAge: 300 });
			const session = makeSession(1_000);
			expect(freshness.guard(session)).toBeNull();
		});

		it("returns 403 Response for stale session", async () => {
			const freshness = createSessionFreshnessModule({ freshAge: 300 });
			const session = makeSession(600_000);
			const response = freshness.guard(session);

			expect(response).not.toBeNull();
			expect(response!.status).toBe(403);

			const body = (await response!.json()) as { error: { code: string } };
			expect(body.error.code).toBe("SESSION_NOT_FRESH");
		});
	});
});
