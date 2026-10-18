/** `mcp.cimd.block` writes a `client` revocation row, so tokens of the blocked client die in live mode on every instance. */
import { describe, expect, it } from "vitest";
import { createCimdAdmin } from "../src/mcp/cimd-admin.js";
import { createInMemoryBlockStore } from "../src/mcp/memory-stores.js";
import { validateAccessToken } from "../src/mcp/validate.js";
import { bootEndpoints, RS_AUDIENCE } from "./mcp-endpoint-fixture.js";

const CLIENT_URL = "https://app.example.com/oauth/client.json";
const OTHER_URL = "https://other.example.com/oauth/client.json";

const refuse = async () =>
	({ success: false, error: { code: "INVALID_CLIENT", message: "x" } }) as const;

describe("mcp.cimd.block and the client revocation row", () => {
	it("a URL block revokes that client's live tokens on every instance and spares others", async () => {
		const w = await bootEndpoints();
		const one = w.instance();
		const two = w.instance();
		const mine = await w.issue({ clientId: CLIENT_URL });
		const theirs = await w.issue({ clientId: OTHER_URL });
		const live = (ctx: typeof one, token: string) =>
			validateAccessToken(ctx, token, { expectedAudience: RS_AUDIENCE, freshness: "live" });
		expect((await live(two, mine.jwt)).success).toBe(true);

		await new Promise((r) => setTimeout(r, 1100));
		const admin = createCimdAdmin({ ...one, clientBlocks: createInMemoryBlockStore() }, refuse);
		await admin.block({ kind: "url", value: CLIENT_URL, reason: "abuse" });

		for (const ctx of [one, two]) {
			const after = await live(ctx, mine.jwt);
			expect(after.success).toBe(false);
			if (!after.success) {
				expect(after.error.details?.revocation).toMatchObject({ reason: "client_revoked" });
			}
			expect((await live(ctx, theirs.jwt)).success).toBe(true);
		}
	});

	it("a token minted after the block is not caught by the watermark of an earlier block", async () => {
		const w = await bootEndpoints();
		const admin = createCimdAdmin({ ...w.ctx, clientBlocks: createInMemoryBlockStore() }, refuse);
		await admin.block({ kind: "url", value: CLIENT_URL });
		await new Promise((r) => setTimeout(r, 1100));
		const later = await w.issue({ clientId: CLIENT_URL });
		const out = await validateAccessToken(w.ctx, later.jwt, {
			expectedAudience: RS_AUDIENCE,
			freshness: "live",
		});
		expect(out.success).toBe(true);
	});
});
