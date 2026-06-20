/**
 * Tests for @theauth/test-utils
 *
 * Covers:
 *   - factories: createMockUser, createMockSession, createMockAgent, createMockPermission
 *   - mock-server: createMockAuthServer — addUser, removeUser, resolveUser, getUser,
 *     syncUser, setActiveUser, header override, reset
 *   - assertions: expectAuthenticated, expectUnauthenticated, expectPermissionDenied
 */

import type { ActionResult } from "@theauth/react";
import { describe, expect, it } from "vitest";
import {
	expectAuthenticated,
	expectPermissionDenied,
	expectUnauthenticated,
} from "../src/assertions.js";
import {
	createMockAgent,
	createMockPermission,
	createMockSession,
	createMockUser,
} from "../src/factories.js";
import { createMockAuthServer, MOCK_USER_ID_HEADER } from "../src/mock-server.js";

// ─── Factories ────────────────────────────────────────────────────────────────

describe("createMockUser", () => {
	it("returns a user with all required fields", () => {
		const user = createMockUser();
		expect(user.id).toMatch(/^usr_/);
		expect(user.email).toMatch(/@example\.com$/);
		expect(typeof user.name).toBe("string");
	});

	it("applies overrides", () => {
		const user = createMockUser({ email: "alice@acme.com", name: "Alice" });
		expect(user.email).toBe("alice@acme.com");
		expect(user.name).toBe("Alice");
		expect(user.id).toMatch(/^usr_/);
	});

	it("produces unique IDs on each call", () => {
		const a = createMockUser();
		const b = createMockUser();
		expect(a.id).not.toBe(b.id);
	});
});

describe("createMockSession", () => {
	it("returns a session with token, user, and expiresAt", () => {
		const session = createMockSession();
		expect(session.token).toMatch(/^tok_/);
		expect(session.user).toBeDefined();
		expect(session.expiresAt).toBeDefined();
	});

	it("expiresAt is in the future", () => {
		const session = createMockSession();
		const expiresAt = session.expiresAt;
		if (!expiresAt) throw new Error("Expected expiresAt");
		expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());
	});

	it("accepts a custom user override", () => {
		const user = createMockUser({ name: "Bob" });
		const session = createMockSession({ user });
		expect(session.user.name).toBe("Bob");
	});

	it("accepts a custom token", () => {
		const session = createMockSession({ token: "custom-token" });
		expect(session.token).toBe("custom-token");
	});
});

describe("createMockPermission", () => {
	it("returns a permission with resource and actions", () => {
		const perm = createMockPermission();
		expect(perm.resource).toBeTruthy();
		expect(Array.isArray(perm.actions)).toBe(true);
	});

	it("applies overrides", () => {
		const perm = createMockPermission({ resource: "files", actions: ["read", "write"] });
		expect(perm.resource).toBe("files");
		expect(perm.actions).toEqual(["read", "write"]);
	});
});

describe("createMockAgent", () => {
	it("returns an agent with all required fields", () => {
		const agent = createMockAgent();
		expect(agent.id).toMatch(/^agt_/);
		expect(agent.token).toMatch(/^agt_tok_/);
		expect(agent.status).toBe("active");
		expect(["autonomous", "delegated", "service"]).toContain(agent.type);
		expect(Array.isArray(agent.permissions)).toBe(true);
	});

	it("applies overrides", () => {
		const agent = createMockAgent({ type: "autonomous", status: "revoked" });
		expect(agent.type).toBe("autonomous");
		expect(agent.status).toBe("revoked");
	});

	it("produces unique IDs on each call", () => {
		const a = createMockAgent();
		const b = createMockAgent();
		expect(a.id).not.toBe(b.id);
	});

	it("accepts custom permissions", () => {
		const perms = [createMockPermission({ resource: "secrets", actions: ["read"] })];
		const agent = createMockAgent({ permissions: perms });
		expect(agent.permissions[0]?.resource).toBe("secrets");
	});
});

// ─── Mock auth server ─────────────────────────────────────────────────────────

describe("createMockAuthServer", () => {
	it("starts with an empty store", () => {
		const server = createMockAuthServer();
		expect(server.users.size).toBe(0);
	});

	it("addUser stores a user", () => {
		const server = createMockAuthServer();
		const user = createMockUser();
		server.addUser(user);
		expect(server.users.size).toBe(1);
		expect(server.users.get(user.id)?.email).toBe(user.email);
	});

	it("removeUser deletes a user", () => {
		const server = createMockAuthServer();
		const user = createMockUser();
		server.addUser(user);
		server.removeUser(user.id);
		expect(server.users.size).toBe(0);
	});

	it("getUser returns null for unknown ID", async () => {
		const server = createMockAuthServer();
		const result = await server.getUser("unknown");
		expect(result).toBeNull();
	});

	it("getUser returns the stored user", async () => {
		const server = createMockAuthServer();
		const user = createMockUser();
		server.addUser(user);
		const found = await server.getUser(user.id);
		expect(found?.id).toBe(user.id);
	});

	it("resolveUser returns null when no active user is set", async () => {
		const server = createMockAuthServer();
		const result = await server.resolveUser(new Request("https://example.com"));
		expect(result).toBeNull();
	});

	it("resolveUser returns the active user after setActiveUser", async () => {
		const server = createMockAuthServer();
		const user = createMockUser();
		server.addUser(user);
		server.setActiveUser(user.id);

		const result = await server.resolveUser(new Request("https://example.com"));
		expect(result?.id).toBe(user.id);
	});

	it("resolveUser returns null when active user is not in the store", async () => {
		const server = createMockAuthServer();
		server.setActiveUser("ghost-id");
		const result = await server.resolveUser(new Request("https://example.com"));
		expect(result).toBeNull();
	});

	it("resolveUser uses header override over active user", async () => {
		const server = createMockAuthServer();
		const userA = createMockUser();
		const userB = createMockUser();
		server.addUser(userA);
		server.addUser(userB);
		server.setActiveUser(userA.id);

		const req = new Request("https://example.com", {
			headers: { [MOCK_USER_ID_HEADER]: userB.id },
		});
		const result = await server.resolveUser(req);
		expect(result?.id).toBe(userB.id);
	});

	it("syncUser adds/updates a user in the store", async () => {
		const server = createMockAuthServer();
		const user = createMockUser({ name: "Before" });
		server.addUser(user);

		await server.syncUser({ ...user, name: "After" });
		const updated = await server.getUser(user.id);
		expect(updated?.name).toBe("After");
	});

	it("removeUser clears active user if it matches", async () => {
		const server = createMockAuthServer();
		const user = createMockUser();
		server.addUser(user);
		server.setActiveUser(user.id);
		server.removeUser(user.id);

		const result = await server.resolveUser(new Request("https://example.com"));
		expect(result).toBeNull();
	});

	it("reset clears all users and active user", async () => {
		const server = createMockAuthServer();
		const user = createMockUser();
		server.addUser(user);
		server.setActiveUser(user.id);
		server.reset();

		expect(server.users.size).toBe(0);
		const result = await server.resolveUser(new Request("https://example.com"));
		expect(result).toBeNull();
	});

	it("multiple independent server instances do not share state", () => {
		const a = createMockAuthServer();
		const b = createMockAuthServer();
		a.addUser(createMockUser());
		expect(b.users.size).toBe(0);
	});
});

// ─── Assertions ───────────────────────────────────────────────────────────────

describe("expectAuthenticated", () => {
	it("does not throw for a success result", () => {
		const result: ActionResult = { success: true, data: undefined };
		expect(() => expectAuthenticated(result)).not.toThrow();
	});

	it("throws for a failure result", () => {
		const result: ActionResult = { success: false, error: "Invalid credentials" };
		expect(() => expectAuthenticated(result)).toThrow(/Invalid credentials/);
	});

	it("includes the error message in the thrown error", () => {
		const result: ActionResult = { success: false, error: "Token expired" };
		expect(() => expectAuthenticated(result)).toThrow("Token expired");
	});
});

describe("expectUnauthenticated", () => {
	it("does not throw for a failure result", () => {
		const result: ActionResult = { success: false, error: "Not logged in" };
		expect(() => expectUnauthenticated(result)).not.toThrow();
	});

	it("throws when the result succeeded", () => {
		const result: ActionResult = { success: true, data: undefined };
		expect(() => expectUnauthenticated(result)).toThrow(/success/);
	});
});

describe("expectPermissionDenied", () => {
	it("does not throw when error contains 'permission'", () => {
		const result: ActionResult = {
			success: false,
			error: "permission denied for this resource",
		};
		expect(() => expectPermissionDenied(result)).not.toThrow();
	});

	it("is case-insensitive by default", () => {
		const result: ActionResult = { success: false, error: "PERMISSION DENIED" };
		expect(() => expectPermissionDenied(result)).not.toThrow();
	});

	it("throws when the result succeeded", () => {
		const result: ActionResult = { success: true, data: undefined };
		expect(() => expectPermissionDenied(result)).toThrow(/success/);
	});

	it("throws when error does not contain the match string", () => {
		const result: ActionResult = { success: false, error: "network error" };
		expect(() => expectPermissionDenied(result)).toThrow(/permission/i);
	});

	it("accepts a custom match string", () => {
		const result: ActionResult = { success: false, error: "not allowed to do that" };
		expect(() => expectPermissionDenied(result, "not allowed")).not.toThrow();
	});

	it("throws when custom match string is absent", () => {
		const result: ActionResult = { success: false, error: "expired session" };
		expect(() => expectPermissionDenied(result, "forbidden")).toThrow(/forbidden/);
	});
});
