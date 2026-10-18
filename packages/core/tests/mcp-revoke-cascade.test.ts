/**
 * Parent token revocation cascades to exchanged children (review finding M4, probe P5). Every
 * exchanged token carries its ancestors' jtis (`theauth_pjti`, root first); a revoked ancestor
 * denies the child. Live: next call. Cached: within the poll window. Offline: on the next live
 * revalidate (offline mode reads only the jti denylist for the token's own jti, by design).
 */
import { describe, expect, it } from "vitest";
import { MCP_PARENT_JTI_CLAIM } from "../src/mcp/revocation-types.js";
import {
	call,
	delegate,
	exchange,
	exchangeOk,
	expectDead,
	MODES,
	modules,
	newAgent,
	rfc7009Revoke,
	userToken,
} from "./mcp-binding-fixtures.js";
import { bootDb } from "./mcp-db-harness.js";
import { decodePayload } from "./mcp-test-harness.js";

async function world() {
	const base = await bootDb();
	const owner = base.userId;
	const a = await newAgent(base.auth, owner, "a");
	const b = await newAgent(base.auth, owner, "b");
	const c = await newAgent(base.auth, owner, "c");
	await delegate(base.auth, a, b);
	await delegate(base.auth, b, c);
	const mods = await modules(base.auth, owner, [
		{ id: "plain" },
		{ id: "app", agentId: a },
		{ id: "xb", agentId: b },
		{ id: "xc", agentId: c },
	]);
	return { auth: base.auth, mods };
}

/** A's user token, exchanged into B's token, exchanged into C's token. */
async function chain(w: Awaited<ReturnType<typeof world>>) {
	const root = await userToken(w.mods.live, "app");
	const tb = await exchangeOk(w.mods.live, "xb", root.access_token);
	const tc = await exchangeOk(w.mods.live, "xc", tb);
	return { root, tb, tc };
}

const jtiOf = (token: string) => decodePayload(token).jti as string;
const parentsOf = (token: string) => decodePayload(token)[MCP_PARENT_JTI_CLAIM];

describe("exchanged tokens name their ancestors", () => {
	it("theauth_pjti lists ancestor jtis root first; ordinary tokens carry none", async () => {
		const w = await world();
		const { root, tb, tc } = await chain(w);
		expect(parentsOf(root.access_token)).toBeUndefined();
		expect(parentsOf(tb)).toEqual([jtiOf(root.access_token)]);
		expect(parentsOf(tc)).toEqual([jtiOf(root.access_token), jtiOf(tb)]);
	});
});

describe("revoking a parent token kills every token exchanged from it", () => {
	for (const mode of MODES) {
		it(`${mode}: RFC 7009 revoke of A's token kills B's and C's tokens`, async () => {
			const w = await world();
			const { root, tb, tc } = await chain(w);
			expect((await call(w.mods[mode], tc)).status).toBe(200);
			await rfc7009Revoke(w.mods.live, "app", root.access_token, "access_token");
			await expectDead(w.mods, mode, tb);
			await expectDead(w.mods, mode, tc);
		});

		it(`${mode}: revoking A's refresh family kills C's token`, async () => {
			const w = await world();
			const { root, tc } = await chain(w);
			expect(root.refresh_token).toBeTruthy();
			await rfc7009Revoke(w.mods.live, "app", root.refresh_token as string, "refresh_token");
			await expectDead(w.mods, mode, tc);
		});
	}

	it("revoking the middle token kills C but leaves A alive", async () => {
		const w = await world();
		const { root, tb, tc } = await chain(w);
		await rfc7009Revoke(w.mods.live, "xb", tb, "access_token");
		expect((await call(w.mods.live, tc)).status).toBe(401);
		expect((await call(w.mods.live, root.access_token)).status).toBe(200);
	});

	it("unbound chains cascade too (no agent anywhere)", async () => {
		const w = await world();
		const root = await userToken(w.mods.live, "plain");
		const child = await exchangeOk(w.mods.live, "plain", root.access_token);
		const grandchild = await exchangeOk(w.mods.live, "plain", child);
		expect(decodePayload(grandchild).theauth_dlg).toBeUndefined();
		await rfc7009Revoke(w.mods.live, "plain", root.access_token, "access_token");
		expect((await call(w.mods.live, grandchild)).status).toBe(401);
		expect((await call(w.mods.cached, grandchild)).status).toBe(401);
	});

	it("a child of a revoked parent cannot be exchanged again", async () => {
		const w = await world();
		const { root, tb } = await chain(w);
		await rfc7009Revoke(w.mods.live, "app", root.access_token, "access_token");
		const res = await exchange(w.mods.live, "xc", tb);
		expect(res.success).toBe(false);
	});
});
