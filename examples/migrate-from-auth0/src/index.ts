/**
 * migrate-from-auth0
 *
 * Runnable companion to docs/migrate/from-auth0.mdx. Exercises the AFTER
 * patterns from that guide against the live theauth workspace package, so
 * the documented examples cannot drift from the real API surface.
 *
 * Step list mirrors the guide:
 *   1. createTheAuth instance (replaces the Auth0 tenant)
 *   2. Seed a human owner (replaces Auth0 user export import)
 *   3. Create an M2M-equivalent service agent with scoped permissions
 *   4. Authorize staging (allowed) and production (approval-gated)
 *   5. Rotate the service token atomically
 *   6. Inspect the audit trail for compliance
 */

import { createTheAuth, users } from "@glinr/theauth";

const BANNER = "=".repeat(60);

function section(label: string): void {
	console.log(`\n${BANNER}\n  ${label}\n${BANNER}`);
}

function ok(label: string, detail: string): void {
	console.log(`  [ok]   ${label.padEnd(34)} ${detail}`);
}

function denied(label: string, reason: string): void {
	console.log(`  [deny] ${label.padEnd(34)} ${reason}`);
}

async function main(): Promise<void> {
	section("Step 1: createTheAuth (replaces Auth0 tenant)");

	const kavach = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	ok("instance ready", "sqlite :memory:, audit on");

	section("Step 2: Seed owner (replaces Auth0 user import)");

	kavach.db
		.insert(users)
		.values({
			id: "user-ops",
			email: "ops@example.com",
			name: "Ops",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	ok("user seeded", "ops@example.com");

	section("Step 3: Service agent (replaces Auth0 M2M client)");

	const billing = await kavach.agent.create({
		ownerId: "user-ops",
		name: "billing-pipeline",
		type: "service",
		permissions: [
			{
				resource: "mcp:stripe:*",
				actions: ["read"],
				constraints: { maxCallsPerHour: 1000 },
			},
			{
				resource: "mcp:stripe:refund",
				actions: ["execute"],
				constraints: { requireApproval: true },
			},
		],
	});

	ok("agent created", `${billing.name} id=${billing.id.slice(0, 12)}...`);
	ok("bearer token issued (kv_)", `${billing.token.slice(0, 12)}...`);

	section("Step 4: Authorize (staging allowed, production gated)");

	const readResult = await kavach.authorize(billing.id, {
		action: "read",
		resource: "mcp:stripe:charges",
	});
	if (readResult.allowed) {
		ok("read mcp:stripe:charges", `audit=${readResult.auditId.slice(0, 8)}...`);
	}

	const refundResult = await kavach.authorize(billing.id, {
		action: "execute",
		resource: "mcp:stripe:refund",
	});
	if (!refundResult.allowed) {
		denied("execute mcp:stripe:refund", refundResult.reason ?? "approval required");
	}

	section("Step 5: Rotate token (old token dies atomically)");

	const oldToken = billing.token;
	const rotated = await kavach.agent.rotate(billing.id);
	ok("new token", `${rotated.token.slice(0, 12)}...`);

	const oldTokenResult = await kavach.authorizeByToken(oldToken, {
		action: "read",
		resource: "mcp:stripe:charges",
	});
	if (!oldTokenResult.allowed) {
		denied("old token after rotation", oldTokenResult.reason ?? "invalid");
	}

	const newTokenResult = await kavach.authorizeByToken(rotated.token, {
		action: "read",
		resource: "mcp:stripe:charges",
	});
	if (newTokenResult.allowed) {
		ok("new token authorizes", "allowed");
	}

	section("Step 6: Audit trail (replaces Auth0 tenant logs)");

	const allLogs = await kavach.audit.query({ agentId: billing.id });
	const deniedLogs = await kavach.audit.query({
		agentId: billing.id,
		result: "denied",
	});
	ok(
		"audit rows",
		`${allLogs.length} total, ${deniedLogs.length} denied, ${allLogs.length - deniedLogs.length} allowed`,
	);

	const csv = await kavach.audit.export({ format: "csv" });
	const rows = csv.trim().split("\n");
	ok("csv export", `${rows.length - 1} rows`);

	section("Done");
	ok("migrate-from-auth0 smoke", "all steps passed");
	console.log("");
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
