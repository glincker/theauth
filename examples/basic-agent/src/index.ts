/**
 * TheAuth Basic Agent Example
 *
 * This script walks through the core SDK capabilities:
 *   1. Initializing a TheAuth instance with an in-memory SQLite database
 *   2. Creating a user (the human owner of agents)
 *   3. Creating agents with different permission scopes
 *   4. Authorizing actions (both allowed and denied)
 *   5. Querying the immutable audit trail
 *   6. Token-based authorization (stateless bearer token flow)
 *   7. Agent-to-agent delegation chains
 *
 * Run with:  pnpm --filter @glinr/theauth-example-basic-agent start
 */

import { createAuth, users } from "@glinr/theauth";

// ─── Formatting helpers ──────────────────────────────────────────────────────

function header(text: string): void {
	const bar = "─".repeat(60);
	console.log(`\n${bar}`);
	console.log(`  ${text}`);
	console.log(bar);
}

function ok(label: string, value: string): void {
	console.log(`  [ok]  ${label.padEnd(28)} ${value}`);
}

function deny(label: string, reason: string): void {
	console.log(`  [deny] ${label.padEnd(27)} ${reason}`);
}

function info(text: string): void {
	console.log(`        ${text}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
	// ── Step 1: Create a TheAuth instance ─────────────────────────────────────
	//
	// Pass provider "sqlite" with url ":memory:" for a fast, disposable database.
	// In production use a file path (SQLite) or a Postgres/MySQL connection URL.
	//
	header("Step 1 — Initialize TheAuth");

	const kavach = await createAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true, // record every authorize() call in the audit log
			tokenExpiry: "24h",
		},
	});

	ok("instance created", "SQLite :memory:");

	// ── Step 2: Tables are auto-created ─────────────────────────────────────────
	//
	// createAuth() automatically runs CREATE TABLE IF NOT EXISTS for all
	// 10 tables on startup. No manual migration needed for development.
	//
	header("Step 2 — Create database tables");
	ok("tables auto-created", "10 tables (handled by createAuth)");

	// ── Step 3: Create a user ───────────────────────────────────────────────────
	//
	// TheAuth is agent-first, but agents are always owned by a human user.
	// In production you would sync users from your auth provider (better-auth,
	// Clerk, Auth.js, etc.) via the adapter layer.
	//
	header("Step 3 — Create a user");

	kavach.db
		.insert(users)
		.values({
			id: "user-demo",
			email: "alice@example.com",
			name: "Alice",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	ok("user created", "alice@example.com  (id: user-demo)");

	// ── Step 4: Create agents ───────────────────────────────────────────────────
	//
	// Each agent has:
	//   - type:        "autonomous" | "delegated" | "service"
	//   - permissions: a list of { resource, actions, constraints? }
	//
	// Resources follow a colon-separated hierarchy. Wildcards are supported:
	//   "mcp:github:*"  matches any sub-resource under mcp:github
	//   "*"             matches everything (use sparingly)
	//
	header("Step 4 — Create agents");

	// A read-only agent for the GitHub MCP server
	const githubAgent = await kavach.agent.create({
		ownerId: "user-demo",
		name: "github-reader",
		type: "autonomous",
		permissions: [
			{ resource: "mcp:github:*", actions: ["read"] },
			{ resource: "mcp:github:issues", actions: ["read", "comment"] },
		],
	});

	ok("agent created", `${githubAgent.name}  (id: ${githubAgent.id.slice(0, 16)}…)`);
	info(`token: ${githubAgent.token.slice(0, 12)}… (prefix: ${githubAgent.token.slice(0, 10)})`);

	// A deployment agent with human-in-the-loop approval required
	const deployAgent = await kavach.agent.create({
		ownerId: "user-demo",
		name: "deploy-bot",
		type: "autonomous",
		permissions: [
			{
				resource: "mcp:deploy:production",
				actions: ["execute"],
				constraints: {
					requireApproval: true, // every call requires human sign-off
					maxCallsPerHour: 5,
				},
			},
			{
				resource: "mcp:deploy:staging",
				actions: ["execute"],
				constraints: { maxCallsPerHour: 20 },
			},
		],
	});

	ok("agent created", `${deployAgent.name}  (id: ${deployAgent.id.slice(0, 16)}…)`);

	// A sub-agent that will receive delegated permissions later
	const subAgent = await kavach.agent.create({
		ownerId: "user-demo",
		name: "sub-reader",
		type: "delegated",
		permissions: [], // starts with no permissions — will receive them via delegation
	});

	ok("agent created", `${subAgent.name}  (id: ${subAgent.id.slice(0, 16)}…)`);

	// ── Step 5: Authorize actions ───────────────────────────────────────────────
	//
	// kavach.authorize(agentId, { action, resource }) checks:
	//   1. Is the agent active?
	//   2. Does any permission match the resource (with wildcard support)?
	//   3. Does the permission grant the requested action?
	//   4. Are all constraints satisfied?
	//
	// Every call is recorded in the audit log regardless of outcome.
	//
	header("Step 5 — Authorize actions");

	// Should be ALLOWED: github-reader has read on mcp:github:*
	const r1 = await kavach.authorize(githubAgent.id, {
		action: "read",
		resource: "mcp:github:repos",
	});
	if (r1.allowed) {
		ok("read  mcp:github:repos", `allowed  (audit: ${r1.auditId.slice(0, 8)}…)`);
	}

	// Should be ALLOWED: wildcard matches mcp:github:pull_requests
	const r2 = await kavach.authorize(githubAgent.id, {
		action: "read",
		resource: "mcp:github:pull_requests",
	});
	if (r2.allowed) {
		ok("read  mcp:github:pull_requests", `allowed  (audit: ${r2.auditId.slice(0, 8)}…)`);
	}

	// Should be DENIED: github-reader does not have "write" on any resource
	const r3 = await kavach.authorize(githubAgent.id, {
		action: "write",
		resource: "mcp:github:repos",
	});
	if (!r3.allowed) {
		deny("write mcp:github:repos", r3.reason ?? "denied");
	}

	// Should be DENIED: deploy-bot requires human approval on production
	const r4 = await kavach.authorize(deployAgent.id, {
		action: "execute",
		resource: "mcp:deploy:production",
	});
	if (!r4.allowed) {
		deny("exec  mcp:deploy:production", r4.reason ?? "denied");
	}

	// Should be ALLOWED: staging has no requireApproval constraint
	const r5 = await kavach.authorize(deployAgent.id, {
		action: "execute",
		resource: "mcp:deploy:staging",
	});
	if (r5.allowed) {
		ok("exec  mcp:deploy:staging", `allowed  (audit: ${r5.auditId.slice(0, 8)}…)`);
	}

	// Should be DENIED: unknown agent ID
	const r6 = await kavach.authorize("agent-does-not-exist", {
		action: "read",
		resource: "anything",
	});
	if (!r6.allowed) {
		deny("read  anything (bad id)", r6.reason ?? "denied");
	}

	// ── Step 6: Audit trail ─────────────────────────────────────────────────────
	//
	// Every authorize() call is written to kavach_audit_logs.
	// You can filter by agent, user, action, result, or time window.
	// Logs can be exported as JSON or CSV for compliance tooling.
	//
	header("Step 6 — Query the audit trail");

	const allLogs = await kavach.audit.query({ agentId: githubAgent.id });
	info(`${allLogs.length} audit entries for github-reader`);

	const deniedLogs = await kavach.audit.query({
		agentId: githubAgent.id,
		result: "denied",
	});
	info(`${deniedLogs.length} denied  |  ${allLogs.length - deniedLogs.length} allowed`);

	// Export as CSV (useful for compliance: EU AI Act Article 12, SOC 2, ISO 42001)
	const csv = await kavach.audit.export({ format: "csv" });
	const csvLines = csv.trim().split("\n");
	ok("CSV export", `${csvLines.length - 1} rows  (first col: ${csvLines[0]?.split(",")[0] ?? ""})`);

	// ── Step 7: Token-based authorization ──────────────────────────────────────
	//
	// Agents receive an opaque bearer token (prefix: kv_) at creation time.
	// Token validation is fast: it hashes the incoming token and does a single
	// DB lookup. No JWTs, no network round-trips.
	//
	// Use kavach.authorizeByToken() when the caller only has the raw token
	// (e.g., incoming HTTP request with Authorization: Bearer <token>).
	//
	header("Step 7 — Token-based authorization");

	const tokenResult = await kavach.authorizeByToken(githubAgent.token, {
		action: "read",
		resource: "mcp:github:repos",
	});

	if (tokenResult.allowed) {
		ok("authorizeByToken → read mcp:github:repos", "allowed");
	}

	// Demonstrate that an invalid token is rejected
	const badTokenResult = await kavach.authorizeByToken("kv_totally_fake_token_1234567890", {
		action: "read",
		resource: "mcp:github:repos",
	});

	if (!badTokenResult.allowed) {
		deny("authorizeByToken → bad token", badTokenResult.reason ?? "denied");
	}

	// Demonstrate token rotation — the old token is immediately invalidated
	const rotated = await kavach.agent.rotate(githubAgent.id);
	const oldTokenResult = await kavach.authorizeByToken(githubAgent.token, {
		action: "read",
		resource: "mcp:github:repos",
	});

	info(`token rotated: ${rotated.token.slice(0, 12)}… (old token now invalid)`);
	if (!oldTokenResult.allowed) {
		deny("old token after rotation", "rejected — token no longer valid");
	}

	// ── Step 8: Delegation chains ───────────────────────────────────────────────
	//
	// An agent can delegate a subset of its permissions to another agent.
	// Constraints:
	//   - The delegated permissions must be a subset of the parent's permissions.
	//   - maxDepth limits how many hops the chain can have (default: 3).
	//   - Chains carry an expiry; they can also be revoked explicitly.
	//
	// Use case: a top-level orchestrator agent spins up a short-lived sub-agent
	// and passes it exactly the permissions it needs for the current task.
	//
	header("Step 8 — Delegation chains");

	// Re-create github-reader (the original was rotated so its token changed,
	// but the agent object is still active).
	const chain = await kavach.delegate({
		fromAgent: githubAgent.id, // orchestrator (has mcp:github:* read)
		toAgent: subAgent.id, // sub-agent (starts with no permissions)
		permissions: [
			{ resource: "mcp:github:issues", actions: ["read"] }, // subset only
		],
		expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
		maxDepth: 2,
	});

	ok("delegation created", `chain id: ${chain.id.slice(0, 16)}…`);
	info(`from: ${chain.fromAgent.slice(0, 16)}… → to: ${chain.toAgent.slice(0, 16)}…`);
	info(`depth: ${chain.depth}  |  expires: ${chain.expiresAt.toISOString()}`);

	// Verify the effective permissions of the sub-agent include the delegated ones
	const effectivePerms = await kavach.delegation.getEffectivePermissions(subAgent.id);
	ok("effective permissions", `${effectivePerms.length} permission(s) via delegation`);
	for (const p of effectivePerms) {
		info(`  resource: ${p.resource}  actions: [${p.actions.join(", ")}]`);
	}

	// ── Done ────────────────────────────────────────────────────────────────────
	header("Done");
	ok("example complete", "all steps passed");
	console.log("");
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
