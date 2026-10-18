/**
 * Live revocation of delegated MCP access, in one runnable script (about 30 seconds on screen).
 *
 *   npx tsx examples/mcp-revocation-demo/demo.ts     (from the repo root, after pnpm build)
 *
 * No server, no network, no API key. In memory SQLite.
 */

import type { Delegated, World } from "./helpers.js";
import {
	buildWorld,
	callTool,
	decodePayload,
	header,
	introspect,
	line,
	mintDelegatedToken,
	ORDERS_API,
	STRANGER_API,
	say,
} from "./helpers.js";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function show(label: string, outcome: { status: number; code: string; detail: string }): void {
	line(label, `HTTP ${outcome.status} ${outcome.code}`);
	if (outcome.status !== 200) line("", outcome.detail);
}

/** Print a subset of the audit trail for these agents, in write order (query returns newest first). */
async function printAudit(world: World, agentIds: string[], only: string[]): Promise<void> {
	const rows = (await world.auth.audit.query({})).reverse();
	for (const e of rows) {
		if (!agentIds.includes(e.agentId)) continue;
		const name = e.event?.startsWith("delegation.") ? e.event : e.action;
		if (!only.includes(name)) continue;
		const by = name === "delegation.revoke" ? ` revokedBy=${String(e.parameters?.revokedBy)}` : "";
		line(`${e.result}`, `${name} ${e.resource.replace(/[0-9a-f-]{36}/, "<id>")}${by}`);
		if (e.reason) line("", `reason: ${e.reason}`);
	}
}

async function main(): Promise<void> {
	const world = await buildWorld();
	const { auth, live, cached, offline } = world;

	// 1. Setup
	header("1. Setup: owner, assistant, sub-agent, delegation, MCP client, token exchange");
	say("alice owns an assistant (read, write). The assistant delegates read only to a sub-agent.");
	const d: Delegated = await mintDelegatedToken(world, "alice");
	line("assistant", `alice-assistant (read, write on mcp:reports:*)`);
	line("sub-agent", `alice-sub-agent (no permissions of its own)`);
	line("delegation", `assistant to sub-agent, read on mcp:reports:*`);
	say(
		"The user approves the assistant app (mcp:read mcp:write). The sub-agent app narrows that token (RFC 8693).",
	);
	line("token minted", "scope mcp:read, bound to the delegation (raw token not printed)");

	// 2. Allowed call
	header("2. Call read_report (needs mcp:read)");
	show("read_report", await callTool(world, live, d.token, "read_report", d.assistantId));

	// 3. Denied call and explain
	header("3. Call delete_report (needs mcp:write), then ask explain() why");
	show("delete_report", await callTool(world, live, d.token, "delete_report", d.assistantId));
	const why = await auth.explain(d.subAgentId, "write", "mcp:reports:delete_report");
	if (!why.success) throw new Error(why.error.message);
	line("explain decision", `${why.data.decision} (code ${why.data.code})`);
	line(
		"explain reason",
		why.data.reason
			.replace(d.subAgentId, "<agent>")
			.replace(/"[^"]*sub-agent"/, '"alice-sub-agent"'),
	);
	const near = why.data.nearMisses[0];
	if (near) {
		line(
			"near miss",
			`${near.source} grant ${near.grant.resource} [${near.grant.actions.join(",")}]`,
		);
		line("mismatch", near.mismatch.join(","));
		line("hint", near.hint);
	} else {
		line("near miss", "none reported");
	}

	// 4. Token claims
	header("4. What the token says about who is acting (decoded, not raw)");
	const claims = decodePayload(d.token);
	const label = new Map([
		[d.assistantId, "assistant"],
		[d.subAgentId, "sub-agent"],
		[d.subClientId, "sub-agent app (OAuth client bound to the sub-agent)"],
	]);
	const actChain: string[] = [];
	let act = claims.act as { sub?: string; act?: unknown } | undefined;
	while (act) {
		actChain.push(label.get(act.sub ?? "") ?? `${act.sub ?? "?"}`);
		act = act.act as { sub?: string; act?: unknown } | undefined;
	}
	line("scope", String(claims.scope));
	line("sub (the user)", String(claims.sub));
	line(
		"act chain",
		actChain.length ? `${actChain.join(" -> ")} (outermost is the current actor)` : "none",
	);
	line("agent_id", label.get(String(claims.agent_id)) ?? String(claims.agent_id));
	const dlg = claims.theauth_dlg as { v: number; agt: string[]; lnk: string[] } | undefined;
	if (dlg) {
		line("theauth_dlg.agt", dlg.agt.map((id) => label.get(id) ?? id).join(", "));
		line(
			"theauth_dlg.lnk",
			dlg.lnk.map((id) => (id === d.chainId ? "the delegation above" : id)).join(", "),
		);
	} else {
		line("theauth_dlg", "missing");
	}

	// 5. Revoke the parent delegation
	header("5. alice revokes the delegation. The token is unexpired and its signature is valid");
	await auth.delegation.revoke(d.chainId, { revokedBy: "alice" });
	line("revoked", "the assistant to sub-agent delegation");

	// 6. Next request is rejected
	header("6. Very next request with the same token (live mode)");
	show("read_report", await callTool(world, live, d.token, "read_report", d.assistantId));
	say("Audit rows for alice's agents, in write order:");
	await printAudit(world, [d.assistantId, d.subAgentId], ["delegation.revoke", "mcp.tools.call"]);

	// 7. Other freshness modes
	header("7a. cached mode: a second server instance learns by polling (poll 200ms, bound 1000ms)");
	const c = await mintDelegatedToken(world, "bob-cached");
	show("before revoke", await callTool(world, cached, c.token, "read_report", c.assistantId));
	await auth.delegation.revoke(c.chainId, { revokedBy: "bob-cached" });
	show("right after revoke", await callTool(world, cached, c.token, "read_report", c.assistantId));
	const started = Date.now();
	let outcome = await callTool(world, cached, c.token, "read_report", c.assistantId);
	while (outcome.status === 200 && Date.now() - started < 3000) {
		await sleep(50);
		outcome = await callTool(world, cached, c.token, "read_report", c.assistantId);
	}
	const waited = Date.now() - started;
	show("after the poll", outcome);
	line(
		"within the bound",
		waited <= 1000 + 250 ? "yes (under maxStalenessMs plus timer slack)" : `no, waited ${waited}ms`,
	);
	say("The window above is the price of skipping a database read on every request.");

	header("7b. offline mode: signature and exp only");
	const o = await mintDelegatedToken(world, "carol-offline");
	show("before revoke", await callTool(world, offline, o.token, "read_report", o.assistantId));
	await auth.delegation.revoke(o.chainId, { revokedBy: "carol-offline" });
	await sleep(1500);
	show("1.5s after revoke", await callTool(world, offline, o.token, "read_report", o.assistantId));
	const exp = Number(decodePayload(o.token).exp);
	const left = Math.round((exp * 1000 - Date.now()) / 60000);
	line("still valid for", `about ${left} minutes (until exp), nothing can cut that short`);
	say("Offline is fine when accessTokenTtl is a few minutes. Here it is 3600 seconds on purpose.");
	say("The live module still refuses this same token:");
	show("same token, live", await callTool(world, live, o.token, "read_report", o.assistantId));

	// 8. Introspection
	header("8. Introspection of the revoked token (RFC 7662, always live)");
	const entitled = await introspect(live, ORDERS_API, d.token);
	line("orders-api (listed)", JSON.stringify(entitled));
	const stranger = await introspect(live, STRANGER_API, d.token);
	line("stranger-api", JSON.stringify(stranger));
	say("Only a caller entitled to the audience learns why. Everyone else sees active false.");

	say("Done. Revoke the delegation, and the next live request fails. No token list, no redeploy.");
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
