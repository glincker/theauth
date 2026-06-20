/**
 * Integration test: full auth + agent flow.
 *
 * Covers the complete user journey from account creation through to
 * agent delegation and audit export, using in-memory SQLite throughout.
 *
 * Steps:
 *  1.  Create a TheAuth instance with email OTP auth
 *  2.  Sign up a user (sendCode → verifyCode creates the account)
 *  3.  Verify the user record exists and a session was issued
 *  4.  Sign in again (re-verify) — simulates returning user
 *  5.  Create an agent with scoped permissions
 *  6.  Authorize an allowed action — should succeed
 *  7.  Authorize a denied action — should fail
 *  8.  Check the audit trail has both entries
 *  9.  Delegate permissions to a sub-agent
 * 10.  Authorize the sub-agent via delegation — should succeed
 * 11.  Revoke the primary agent
 * 12.  Verify the revoked agent is denied on all actions
 * 13.  Export the audit trail as CSV and verify structure
 */

import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Kavach } from "../src/kavach.js";
import { createKavach } from "../src/kavach.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SESSION_SECRET = "integration-test-secret-at-least-32-chars-long!!";
const TEST_EMAIL = "alice@example.com";

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

async function createIntegrationKavach(): Promise<{
	kavach: Kavach;
	capturedCodes: Map<string, string>;
}> {
	const capturedCodes = new Map<string, string>();

	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		auth: {
			session: { secret: SESSION_SECRET },
		},
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		emailOtp: {
			sendOtp: vi.fn(async (email: string, code: string) => {
				capturedCodes.set(email, code);
			}),
		},
	});

	return { kavach, capturedCodes };
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("Integration: full auth + agent flow", () => {
	let kavach: Kavach;
	let capturedCodes: Map<string, string>;

	beforeEach(async () => {
		({ kavach, capturedCodes } = await createIntegrationKavach());
	});

	it("completes the full flow end-to-end", async () => {
		// ── Step 1: instance is alive ────────────────────────────────────────
		expect(kavach).toBeDefined();
		expect(kavach.emailOtp).not.toBeNull();

		// ── Step 2: sign up (send OTP) ───────────────────────────────────────
		const sendResult = await kavach.emailOtp?.sendCode(TEST_EMAIL);
		expect(sendResult.sent).toBe(true);

		const signupCode = capturedCodes.get(TEST_EMAIL);
		expect(signupCode).toBeDefined();
		expect(typeof signupCode).toBe("string");
		expect((signupCode as string).length).toBeGreaterThan(0);

		// ── Step 3: verify OTP — creates user + issues session ───────────────
		const signupResult = await kavach.emailOtp?.verifyCode(TEST_EMAIL, signupCode as string);
		expect(signupResult).not.toBeNull();

		const userId = signupResult?.user.id;
		expect(userId).toBeTruthy();
		expect(signupResult?.user.email).toBe(TEST_EMAIL);
		expect(signupResult?.session.token).toBeTruthy();
		expect(signupResult?.session.expiresAt.getTime()).toBeGreaterThan(Date.now());

		// Verify the session token is valid
		const session = await kavach.auth.session?.validate(signupResult?.session.token);
		expect(session).not.toBeNull();
		expect(session?.userId).toBe(userId);

		// ── Step 4: sign in again (returning user re-verifies) ───────────────
		await kavach.emailOtp?.sendCode(TEST_EMAIL);
		const signinCode = capturedCodes.get(TEST_EMAIL);
		expect(signinCode).toBeDefined();

		const signinResult = await kavach.emailOtp?.verifyCode(TEST_EMAIL, signinCode as string);
		expect(signinResult).not.toBeNull();
		// Same user each time
		expect(signinResult?.user.id).toBe(userId);
		// Fresh session token
		expect(signinResult?.session.token).toBeTruthy();

		// ── Step 5: create an agent with permissions ─────────────────────────
		const agent = await kavach.agent.create({
			ownerId: userId,
			name: "data-reader",
			type: "autonomous",
			permissions: [
				{ resource: "reports:monthly", actions: ["read"] },
				{ resource: "reports:annual", actions: ["read", "export"] },
			],
		});

		expect(agent.id).toBeTruthy();
		expect(agent.name).toBe("data-reader");
		expect(agent.status).toBe("active");
		expect(agent.token).toMatch(/^kv_/);
		expect(agent.permissions).toHaveLength(2);

		// ── Step 6: authorize an allowed action ──────────────────────────────
		const allowedResult = await kavach.authorize(agent.id, {
			action: "read",
			resource: "reports:monthly",
		});

		expect(allowedResult.allowed).toBe(true);
		expect(allowedResult.auditId).toBeTruthy();

		// ── Step 7: authorize a denied action ────────────────────────────────
		const deniedResult = await kavach.authorize(agent.id, {
			action: "delete",
			resource: "reports:monthly",
		});

		expect(deniedResult.allowed).toBe(false);
		expect(deniedResult.reason).toBeTruthy();

		// ── Step 8: audit trail has both entries ─────────────────────────────
		const auditLogs = await kavach.audit.query({ agentId: agent.id });
		expect(auditLogs.length).toBeGreaterThanOrEqual(2);

		const results = auditLogs.map((l) => l.result);
		expect(results).toContain("allowed");
		expect(results).toContain("denied");

		// Every entry should reference the correct agent
		for (const entry of auditLogs) {
			expect(entry.agentId).toBe(agent.id);
			expect(entry.timestamp).toBeInstanceOf(Date);
			expect(entry.action).toBeTruthy();
			expect(entry.resource).toBeTruthy();
		}

		// ── Step 9: delegate permissions to a sub-agent ──────────────────────
		const subAgent = await kavach.agent.create({
			ownerId: userId,
			name: "sub-reader",
			type: "delegated",
			permissions: [],
		});

		const delegationChain = await kavach.delegate({
			fromAgent: agent.id,
			toAgent: subAgent.id,
			permissions: [{ resource: "reports:monthly", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
		});

		expect(delegationChain.id).toBeTruthy();
		expect(delegationChain.fromAgent).toBe(agent.id);
		expect(delegationChain.toAgent).toBe(subAgent.id);
		expect(delegationChain.depth).toBe(1);

		// Effective permissions should now include the delegated grant
		const effectivePerms = await kavach.delegation.getEffectivePermissions(subAgent.id);
		expect(effectivePerms.length).toBeGreaterThanOrEqual(1);
		const delegatedPerm = effectivePerms.find((p) => p.resource === "reports:monthly");
		expect(delegatedPerm).toBeDefined();
		expect(delegatedPerm?.actions).toContain("read");

		// ── Step 10: authorize via delegation ────────────────────────────────
		const delegatedAllowed = await kavach.authorize(subAgent.id, {
			action: "read",
			resource: "reports:monthly",
		});

		expect(delegatedAllowed.allowed).toBe(true);

		// An action not in the delegation should be denied
		const delegatedDenied = await kavach.authorize(subAgent.id, {
			action: "export",
			resource: "reports:monthly",
		});

		expect(delegatedDenied.allowed).toBe(false);

		// ── Step 11: revoke the primary agent ────────────────────────────────
		await kavach.agent.revoke(agent.id);

		const revokedAgent = await kavach.agent.get(agent.id);
		expect(revokedAgent).not.toBeNull();
		expect(revokedAgent?.status).toBe("revoked");

		// ── Step 12: revoked agent is denied on all actions ──────────────────
		const afterRevokeResult = await kavach.authorize(agent.id, {
			action: "read",
			resource: "reports:monthly",
		});

		expect(afterRevokeResult.allowed).toBe(false);
		expect(afterRevokeResult.reason).toMatch(/revoked/i);

		// Token validation should also fail for the revoked agent
		const tokenResult = await kavach.agent.validateToken(agent.token);
		expect(tokenResult).toBeNull();

		// ── Step 13: export audit trail as CSV ───────────────────────────────
		const csv = await kavach.audit.export({ format: "csv" });

		// Header row
		expect(csv).toContain("id,agentId,userId");
		expect(csv).toContain("action");
		expect(csv).toContain("resource");
		expect(csv).toContain("result");

		// Data rows — both agents should appear
		expect(csv).toContain(agent.id);
		expect(csv).toContain("allowed");
		expect(csv).toContain("denied");

		// Should be valid multi-line CSV
		const csvLines = csv.split("\n").filter((l) => l.trim().length > 0);
		// At minimum: header + entries from steps 6, 7, 10 (allow), 10 (deny)
		expect(csvLines.length).toBeGreaterThanOrEqual(5);
	});

	it("rejects delegation that exceeds parent agent permissions", async () => {
		await kavach.emailOtp?.sendCode(TEST_EMAIL);
		const code = capturedCodes.get(TEST_EMAIL) as string;
		const { user } = (await kavach.emailOtp?.verifyCode(TEST_EMAIL, code))!;

		const parent = await kavach.agent.create({
			ownerId: user.id,
			name: "limited-parent",
			type: "autonomous",
			permissions: [{ resource: "docs:*", actions: ["read"] }],
		});

		const child = await kavach.agent.create({
			ownerId: user.id,
			name: "over-reaching-child",
			type: "delegated",
			permissions: [],
		});

		await expect(
			kavach.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "docs:*", actions: ["read", "write", "delete"] }],
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
			}),
		).rejects.toThrow("subset");
	});

	it("sub-agent loses access after delegation is revoked", async () => {
		await kavach.emailOtp?.sendCode(TEST_EMAIL);
		const code = capturedCodes.get(TEST_EMAIL) as string;
		const { user } = (await kavach.emailOtp?.verifyCode(TEST_EMAIL, code))!;

		const parent = await kavach.agent.create({
			ownerId: user.id,
			name: "parent",
			type: "autonomous",
			permissions: [{ resource: "metrics:*", actions: ["read"] }],
		});

		const child = await kavach.agent.create({
			ownerId: user.id,
			name: "child",
			type: "delegated",
			permissions: [],
		});

		const chain = await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "metrics:dashboard", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// Access granted before revocation
		const before = await kavach.authorize(child.id, {
			action: "read",
			resource: "metrics:dashboard",
		});
		expect(before.allowed).toBe(true);

		// Revoke the delegation chain
		await kavach.delegation.revoke(chain.id);

		// Access denied after revocation
		const after = await kavach.authorize(child.id, {
			action: "read",
			resource: "metrics:dashboard",
		});
		expect(after.allowed).toBe(false);
	});

	it("audit export as JSON contains all fields", async () => {
		await kavach.emailOtp?.sendCode(TEST_EMAIL);
		const code = capturedCodes.get(TEST_EMAIL) as string;
		const { user } = (await kavach.emailOtp?.verifyCode(TEST_EMAIL, code))!;

		const agent = await kavach.agent.create({
			ownerId: user.id,
			name: "json-export-agent",
			type: "autonomous",
			permissions: [{ resource: "files:*", actions: ["read"] }],
		});

		await kavach.authorize(agent.id, { action: "read", resource: "files:report.pdf" });
		await kavach.authorize(agent.id, { action: "write", resource: "files:report.pdf" });

		const json = await kavach.audit.export({ format: "json" });
		const entries = JSON.parse(json) as Array<Record<string, unknown>>;

		expect(Array.isArray(entries)).toBe(true);
		expect(entries.length).toBeGreaterThanOrEqual(2);

		// Verify each entry has the expected fields
		for (const entry of entries) {
			expect(typeof entry.id).toBe("string");
			expect(typeof entry.agentId).toBe("string");
			expect(typeof entry.action).toBe("string");
			expect(typeof entry.resource).toBe("string");
			expect(entry.result === "allowed" || entry.result === "denied").toBe(true);
			expect(typeof entry.timestamp).toBe("string"); // serialised as ISO string
		}

		// Check the agent-specific entries appear
		const agentEntries = entries.filter((e) => e.agentId === agent.id);
		expect(agentEntries.length).toBeGreaterThanOrEqual(2);

		const agentResults = new Set(agentEntries.map((e) => e.result));
		expect(agentResults.has("allowed")).toBe(true);
		expect(agentResults.has("denied")).toBe(true);
	});

	it("unique users get independent audit trails", async () => {
		const emailA = `alice-${randomUUID()}@example.com`;
		const emailB = `bob-${randomUUID()}@example.com`;

		// Set up user A
		await kavach.emailOtp?.sendCode(emailA);
		const codeA = capturedCodes.get(emailA) as string;
		const { user: userA } = (await kavach.emailOtp?.verifyCode(emailA, codeA))!;

		// Set up user B
		await kavach.emailOtp?.sendCode(emailB);
		const codeB = capturedCodes.get(emailB) as string;
		const { user: userB } = (await kavach.emailOtp?.verifyCode(emailB, codeB))!;

		const agentA = await kavach.agent.create({
			ownerId: userA.id,
			name: "agent-a",
			type: "autonomous",
			permissions: [{ resource: "workspace:a", actions: ["read"] }],
		});

		const agentB = await kavach.agent.create({
			ownerId: userB.id,
			name: "agent-b",
			type: "autonomous",
			permissions: [{ resource: "workspace:b", actions: ["read"] }],
		});

		await kavach.authorize(agentA.id, { action: "read", resource: "workspace:a" });
		await kavach.authorize(agentB.id, { action: "read", resource: "workspace:b" });

		const logsA = await kavach.audit.query({ agentId: agentA.id });
		const logsB = await kavach.audit.query({ agentId: agentB.id });

		expect(logsA).toHaveLength(1);
		expect(logsB).toHaveLength(1);

		// No cross-contamination
		expect(logsA[0]?.agentId).toBe(agentA.id);
		expect(logsB[0]?.agentId).toBe(agentB.id);
	});
});
