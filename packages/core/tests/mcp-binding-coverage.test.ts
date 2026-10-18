/**
 * Binding coverage (review finding M1, probe P3, and the live demo's findings):
 * - an exchanged token's `agent_id` (and `principal.agent`) is the ACTING agent, the last entry of
 *   `theauth_dlg.agt`, never an agent outside the binding;
 * - revoking any agent in `agt`, or any delegation in `lnk`, kills the token in every mode
 *   (offline: on the next live revalidate);
 * - an ordinary token of a client bound to a delegated agent names the agent's live inbound path,
 *   so a parent delegation revoke is seen in cached and offline modes as well as live.
 */
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import type { McpFreshnessMode } from "../src/mcp/revocation-types.js";
import { MCP_DELEGATION_CLAIM } from "../src/mcp/revocation-types.js";
import {
	agentIdOf,
	call,
	delegate,
	dlgOf,
	exchangeOk,
	expectDead,
	MODES,
	modules,
	newAgent,
	userToken,
} from "./mcp-binding-fixtures.js";
import { bootDb } from "./mcp-db-harness.js";
import { ISSUER, RESOURCE, SECRET } from "./mcp-test-harness.js";

/** alice owns assistant A and sub agent S (A delegates to S), plus an unrelated agent Z. */
async function world() {
	const base = await bootDb();
	const owner = base.userId;
	const a = await newAgent(base.auth, owner, "assistant");
	const s = await newAgent(base.auth, owner, "sub");
	const z = await newAgent(base.auth, owner, "z");
	const link = await delegate(base.auth, a, s);
	const mods = await modules(base.auth, owner, [
		{ id: "plain" },
		{ id: "app", agentId: a },
		{ id: "sub", agentId: s },
		{ id: "zc", agentId: z },
	]);
	return { auth: base.auth, owner, a, s, z, link, mods };
}

type World = Awaited<ReturnType<typeof world>>;

/** The demo flow: the assistant app's user token, narrowed by the sub agent app. */
async function demoToken(w: World): Promise<string> {
	const subject = await userToken(w.mods.live, "app");
	return exchangeOk(w.mods.live, "sub", subject.access_token);
}

describe("exchanged token names the acting agent", () => {
	it("demo flow: agent_id and principal.agent are the sub agent, the chain stays in agt", async () => {
		const w = await world();
		const child = await demoToken(w);
		expect(dlgOf(child)).toEqual({ v: 1, agt: [w.a, w.s], lnk: [w.link] });
		expect(agentIdOf(child)).toBe(w.s);
		const seen = await call(w.mods.live, child);
		expect(seen).toEqual({ status: 200, agent: w.s });
		const session = await w.mods.live.validateToken(child);
		expect(session.success && session.data.binding?.agt).toEqual([w.a, w.s]);
	});

	it("P3: actor token agent wins over the presenting client's agent, which stays out", async () => {
		const w = await world();
		const subject = await userToken(w.mods.live, "plain");
		const actor = await userToken(w.mods.live, "sub");
		const child = await exchangeOk(w.mods.live, "zc", subject.access_token, actor.access_token);
		const dlg = dlgOf(child);
		expect(dlg?.agt).toEqual([w.a, w.s]);
		expect(agentIdOf(child)).toBe(w.s);
		expect(dlg?.agt).not.toContain(w.z);
		// Revoking the presenting client's agent does not matter; it was never in the authority path.
		await w.auth.agent.revoke(w.z);
		expect(await call(w.mods.live, child)).toEqual({ status: 200, agent: w.s });
	});

	it("refused attribution of a rejected call lands under the acting agent", async () => {
		const w = await world();
		const child = await demoToken(w);
		await w.auth.delegation.revoke(w.link);
		const res = await w.mods.live.validateToken(child);
		expect(res.success).toBe(false);
		if (!res.success) {
			const rejected = (res.error.details as { rejected?: { agentId?: string } }).rejected;
			expect(rejected?.agentId).toBe(w.s);
		}
	});

	it("validation refuses a bound token whose agent_id is outside agt", async () => {
		const w = await world();
		const now = Math.floor(Date.now() / 1000);
		const forged = await new SignJWT({
			sub: w.owner,
			client_id: "zc",
			scope: "mcp:read",
			jti: "forged-1",
			agent_id: w.z,
			[MCP_DELEGATION_CLAIM]: { v: 1, agt: [w.s], lnk: [] },
		})
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuer(ISSUER)
			.setAudience(RESOURCE)
			.setIssuedAt(now)
			.setExpirationTime(now + 600)
			.sign(new TextEncoder().encode(SECRET));
		for (const mode of MODES) {
			expect((await call(w.mods[mode], forged)).status).toBe(401);
		}
	});
});

const TARGETS = ["acting agent", "root agent", "delegation"] as const;

describe("revoking anything in the binding kills the exchanged token in every mode", () => {
	for (const mode of MODES) {
		for (const target of TARGETS) {
			it(`${mode}: revoke the ${target}`, async () => {
				const w = await world();
				const child = await demoToken(w);
				expect((await call(w.mods[mode], child)).status).toBe(200);
				if (target === "acting agent") await w.auth.agent.revoke(w.s);
				else if (target === "root agent") await w.auth.agent.revoke(w.a);
				else await w.auth.delegation.revoke(w.link);
				await expectDead(w.mods, mode, child);
			});
		}
	}
});

describe("ordinary tokens of a delegated agent's client carry its inbound path", () => {
	it("authorization code token of the sub agent app names the parent delegation", async () => {
		const w = await world();
		const token = await userToken(w.mods.live, "sub");
		expect(dlgOf(token.access_token)).toEqual({ v: 1, agt: [w.a, w.s], lnk: [w.link] });
		expect(agentIdOf(token.access_token)).toBe(w.s);
	});

	it("an agent with no inbound delegation stays agt [agent], lnk []", async () => {
		const w = await world();
		const token = await userToken(w.mods.live, "app");
		expect(dlgOf(token.access_token)).toEqual({ v: 1, agt: [w.a], lnk: [] });
	});

	it("A to B to C: the C client's token names both links", async () => {
		const w = await world();
		const c = await newAgent(w.auth, w.owner, "c");
		const sc = await delegate(w.auth, w.s, c);
		const mods = await modules(w.auth, w.owner, [{ id: "cc", agentId: c }]);
		const token = await userToken(mods.live, "cc");
		expect(dlgOf(token.access_token)).toEqual({ v: 1, agt: [w.a, w.s, c], lnk: [w.link, sc] });
	});

	for (const mode of MODES) {
		it(`${mode}: parent delegation revoke kills the ordinary token`, async () => {
			const w = await world();
			const token = (await userToken(w.mods.live, "sub")).access_token;
			expect((await call(w.mods[mode], token)).status).toBe(200);
			await w.auth.delegation.revoke(w.link);
			await expectDead(w.mods, mode, token);
		});

		it(`${mode}: exchanging the sub agent app's token keeps the parent link`, async () => {
			const w = await world();
			const subject = (await userToken(w.mods.live, "sub")).access_token;
			const child = await exchangeOk(w.mods.live, "plain", subject);
			expect(dlgOf(child)).toEqual({ v: 1, agt: [w.a, w.s], lnk: [w.link] });
			expect(agentIdOf(child)).toBe(w.s);
			await w.auth.delegation.revoke(w.link);
			await expectDead(w.mods, mode as McpFreshnessMode, child);
		});
	}
});
