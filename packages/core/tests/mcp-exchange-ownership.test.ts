/**
 * Token exchange ownership (review finding M5, probe P4): the subject token's user must own, or be
 * delegated through the chain to, every agent the child binding names. User U can never bind a
 * token to user V's agent through any mix of subject token, actor token and client binding.
 */
import { and, eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { auditLogs } from "../src/db/schema.js";
import type { McpAuthModule } from "../src/mcp/types.js";
import {
	agentIdOf,
	call,
	delegate,
	dlgOf,
	exchange,
	exchangeOk,
	modules,
	newAgent,
	userToken,
} from "./mcp-binding-fixtures.js";
import { bootDb } from "./mcp-db-harness.js";

async function world() {
	const base = await bootDb();
	const u = base.userId;
	const v = (await base.auth.user.create({ email: "stranger@example.com" })).id;
	const aU = await newAgent(base.auth, u, "u-agent");
	const fV = await newAgent(base.auth, v, "v-agent");
	const specs = [{ id: "plain" }, { id: "app", agentId: aU }, { id: "zc", agentId: fV }];
	const asU = (await modules(base.auth, u, specs)).live;
	const asV = (await modules(base.auth, v, specs)).live;
	return { auth: base.auth, u, v, aU, fV, asU, asV };
}

async function refused(
	mcp: McpAuthModule,
	clientId: string,
	subject: string,
	actor?: string,
): Promise<string> {
	const res = await exchange(mcp, clientId, subject, actor);
	expect(res.success).toBe(false);
	if (res.success) return "";
	expect(res.error.code).toBe("INVALID_GRANT");
	return res.error.message;
}

describe("token exchange refuses agents the subject user is not entitled to", () => {
	it("P4: client bound to V's agent cannot exchange U's unbound token", async () => {
		const w = await world();
		const subject = await userToken(w.asU, "plain");
		const message = await refused(w.asU, "zc", subject.access_token);
		expect(message).toMatch(/not entitled/);
		const rows = await w.auth.db
			.select()
			.from(auditLogs)
			.where(and(eq(auditLogs.agentId, w.fV), eq(auditLogs.action, "mcp.token_exchange")));
		expect(rows).toHaveLength(1);
		expect(rows[0]?.result).toBe("denied");
		expect(rows[0]?.userId).toBe(w.v);
		// The row names ids only, never a token value.
		expect(JSON.stringify(rows[0])).not.toContain(subject.access_token);
	});

	it("actor token of V's agent cannot be stacked on U's unbound token", async () => {
		const w = await world();
		const subject = await userToken(w.asU, "plain");
		const vActor = await userToken(w.asV, "zc");
		await refused(w.asU, "plain", subject.access_token, vActor.access_token);
		// U's own token through V's client is no better as an actor token.
		const uViaZc = await userToken(w.asU, "zc");
		await refused(w.asU, "plain", subject.access_token, uViaZc.access_token);
	});

	it("a subject token already bound to V's agent cannot be exchanged by anyone", async () => {
		const w = await world();
		const uViaZc = await userToken(w.asU, "zc");
		expect(dlgOf(uViaZc.access_token)?.agt).toEqual([w.fV]);
		await refused(w.asU, "plain", uViaZc.access_token);
		await refused(w.asU, "app", uViaZc.access_token);
	});

	it("U's agent token cannot be extended to V's agent without a delegation", async () => {
		const w = await world();
		const subject = await userToken(w.asU, "app");
		expect((await refused(w.asU, "zc", subject.access_token)).length).toBeGreaterThan(0);
		const vActor = await userToken(w.asV, "zc");
		await refused(w.asU, "plain", subject.access_token, vActor.access_token);
	});

	it("V cannot bind their token to U's agent either", async () => {
		const w = await world();
		const vSubject = await userToken(w.asV, "plain");
		await refused(w.asV, "app", vSubject.access_token);
	});

	it("allowed when U's own agent delegated to the other agent (entitled through the chain)", async () => {
		const w = await world();
		const link = await delegate(w.auth, w.aU, w.fV);
		const subject = await userToken(w.asU, "app");
		const child = await exchangeOk(w.asU, "zc", subject.access_token);
		expect(dlgOf(child)).toEqual({ v: 1, agt: [w.aU, w.fV], lnk: [link] });
		expect(agentIdOf(child)).toBe(w.fV);
		expect((await call(w.asU, child)).status).toBe(200);
	});

	it("allowed for U's own agent with no delegation (owner hop)", async () => {
		const w = await world();
		const subject = await userToken(w.asU, "plain");
		const child = await exchangeOk(w.asU, "app", subject.access_token);
		expect(dlgOf(child)).toEqual({ v: 1, agt: [w.aU], lnk: [] });
		expect(agentIdOf(child)).toBe(w.aU);
	});
});
