/** Cached mode: a revoke that lands while a read is in flight is never lost, even for callers that joined the read. */
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { attachFreshnessDeps } from "../src/mcp/freshness.js";
import type {
	McpBindingStore,
	McpRevocationEvent,
	McpRevocationStore,
} from "../src/mcp/revocation-types.js";
import type { McpAuthContext } from "../src/mcp/types.js";
import { validateAccessToken } from "../src/mcp/validate.js";

const ISSUER = "https://auth.theauth.test";
const RESOURCE = "https://mcp.theauth.test";
const SECRET = "test-signing-secret-at-least-32-chars-long!!";

function harness() {
	const revoked = new Set<string>();
	let gate: Promise<void> | undefined;
	let reads = 0;
	const store: McpRevocationStore = {
		async revoke() {},
		async isRevoked() {
			return false;
		},
		async revokeMany() {},
		async check(q) {
			reads++;
			// The verdict is read BEFORE the gate: a slow round trip that returns an old answer.
			const hit = revoked.has(q.jti) ? { kind: "jti" as const, id: q.jti } : null;
			await gate;
			return hit;
		},
		async fingerprint() {
			return "0";
		},
		async prune() {
			return 0;
		},
	};
	const bindings: McpBindingStore = {
		async check() {
			return { live: true, validUntil: new Date(Date.now() + 86_400_000) };
		},
		async findLiveLink() {
			return null;
		},
		async agents() {
			return new Map();
		},
	};
	const listeners = new Set<(e: McpRevocationEvent) => void>();
	const ctx = {
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: "https://auth.theauth.test/api/auth",
			signingSecret: SECRET,
			resource: RESOURCE,
			accessTokenTtl: 3600,
			refreshTokenTtl: 86400,
			refreshTokenAbsoluteTtl: 86400,
			codeTtl: 60,
			revocation: { mode: "cached", maxStalenessMs: 60_000, pollIntervalMs: 60_000 },
		},
	} as unknown as McpAuthContext;
	attachFreshnessDeps(ctx, {
		revocations: store,
		bindings,
		subscribe: (l) => {
			listeners.add(l);
			return () => listeners.delete(l);
		},
	});
	return {
		ctx,
		revoke(jti: string) {
			revoked.add(jti);
			for (const l of listeners) l({ kind: "jti", ids: [jti], revokedAt: new Date(), reason: "t" });
		},
		hold() {
			let release: () => void = () => {};
			gate = new Promise<void>((r) => {
				release = r;
			});
			return () => {
				gate = undefined;
				release();
			};
		},
		reads: () => reads,
	};
}

const mint = () =>
	new SignJWT({ scope: "mcp:read", client_id: "c1" })
		.setProtectedHeader({ alg: "HS256" })
		.setIssuer(ISSUER)
		.setAudience(RESOURCE)
		.setSubject("user_1")
		.setJti("jti_1")
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(new TextEncoder().encode(SECRET));

const validate = (ctx: McpAuthContext, token: string) =>
	validateAccessToken(ctx, token, { expectedAudience: RESOURCE });

describe("revoke during an in flight cached read", () => {
	it("the original caller and a caller that joined late both see the revoke", async () => {
		const h = harness();
		const token = await mint();
		const release = h.hold();
		const first = validate(h.ctx, token);
		await new Promise((r) => setTimeout(r, 10));
		expect(h.reads()).toBe(1);
		h.revoke("jti_1");
		// Arrives after the local clear, while the old read is still in flight.
		const late = validate(h.ctx, token);
		await new Promise((r) => setTimeout(r, 10));
		release();
		expect((await first).success).toBe(false);
		expect((await late).success).toBe(false);
	});

	it("does not keep a stale positive in the cache afterwards", async () => {
		const h = harness();
		const token = await mint();
		const release = h.hold();
		const first = validate(h.ctx, token);
		await new Promise((r) => setTimeout(r, 10));
		h.revoke("jti_1");
		release();
		await first;
		expect((await validate(h.ctx, token)).success).toBe(false);
	});
});
