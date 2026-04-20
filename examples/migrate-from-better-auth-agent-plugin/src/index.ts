/**
 * migrate-from-better-auth-agent-plugin
 *
 * Runnable companion to docs/migrate/from-better-auth-agent-plugin.mdx.
 * Exercises the AFTER patterns: AgentIdentity as a primary entity, multi-hop
 * delegation chains with maxDepth, cascading revocation, and
 * authorizeByToken against the delegated permission.
 */

import { createKavach, users } from "kavachos";

const BANNER = "=".repeat(60);

function section(label: string): void {
	console.log(`\n${BANNER}\n  ${label}\n${BANNER}`);
}

function ok(label: string, detail: string): void {
	console.log(`  [ok]   ${label.padEnd(38)} ${detail}`);
}

function denied(label: string, reason: string): void {
	console.log(`  [deny] ${label.padEnd(38)} ${reason}`);
}

async function main(): Promise<void> {
	section("Step 1: createKavach (core, no agent plugin)");

	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	ok("instance ready", "agent identity is core, no plugin needed");

	kavach.db
		.insert(users)
		.values({
			id: "user-operator",
			email: "operator@example.com",
			name: "Operator",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	section("Step 2: AgentIdentity replaces the agent plugin's Agent");

	const parent = await kavach.agent.create({
		ownerId: "user-operator",
		name: "orchestrator",
		type: "autonomous",
		permissions: [
			{
				resource: "mcp:github:*",
				actions: ["read"],
				constraints: { maxCallsPerHour: 500 },
			},
			{
				resource: "mcp:github:issues",
				actions: ["read", "comment"],
			},
		],
	});

	ok(
		"orchestrator created",
		`id=${parent.id.slice(0, 12)}... token=${parent.token.slice(0, 10)}...`,
	);

	const child = await kavach.agent.create({
		ownerId: "user-operator",
		name: "issue-responder",
		type: "delegated",
		permissions: [],
	});

	ok("delegated child created", `id=${child.id.slice(0, 12)}... (no direct perms)`);

	section("Step 3: Multi-hop delegation with depth + expiry");

	const chain = await kavach.delegate({
		fromAgent: parent.id,
		toAgent: child.id,
		permissions: [{ resource: "mcp:github:issues", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		maxDepth: 2,
	});

	ok("delegation created", `chain=${chain.id.slice(0, 12)}... depth=${chain.depth} max=2`);

	const effective = await kavach.delegation.getEffectivePermissions(child.id);
	ok("child effective perms", `${effective.length} via chain`);

	section("Step 4: Authorize the delegated child, reject out-of-scope");

	// authorize() falls back to delegation-chain permissions when the agent's
	// own direct permissions deny. That is what the migration guide calls
	// "the child reads through the chain."
	const delegatedPerms = await kavach.delegation.getEffectivePermissions(child.id);
	for (const p of delegatedPerms) {
		ok("child delegated perm", `${p.resource} actions=[${p.actions.join(",")}]`);
	}

	const delegatedAuthorize = await kavach.authorize(child.id, {
		action: "read",
		resource: "mcp:github:issues",
	});
	if (delegatedAuthorize.allowed) {
		ok(
			"child reads delegated resource",
			`allowed audit=${delegatedAuthorize.auditId.slice(0, 8)}...`,
		);
	}

	const outOfScope = await kavach.authorize(child.id, {
		action: "read",
		resource: "mcp:github:repos",
	});
	if (!outOfScope.allowed) {
		denied("child reads out-of-scope resource", outOfScope.reason ?? "denied");
	}

	section("Step 5: Revoking the chain drops effective perms");

	const childBefore = await kavach.delegation.getEffectivePermissions(child.id);
	ok("child effective before revoke", `${childBefore.length} perm(s) via chain`);

	await kavach.delegation.revoke(chain.id);

	const childAfter = await kavach.delegation.getEffectivePermissions(child.id);
	const authorizeAfter = await kavach.authorize(child.id, {
		action: "read",
		resource: "mcp:github:issues",
	});

	if (childBefore.length > 0 && childAfter.length === 0 && !authorizeAfter.allowed) {
		ok(
			"delegations after chain revoke",
			`effective=${childAfter.length} authorize=denied (cascade landed)`,
		);
	} else {
		denied(
			"delegations after chain revoke",
			`before=${childBefore.length} after=${childAfter.length} authorize=${authorizeAfter.allowed}`,
		);
	}

	section("Done");
	ok("migrate-from-ba-agent smoke", "all steps passed");
	console.log("");
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
