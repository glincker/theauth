/**
 * Tests for the third-party auth adapter integrations.
 *
 * Covers:
 * - betterAuthAdapter: resolves user via getSession, maps fields, handles null
 *   session, handles errors gracefully
 * - authJsAdapter: resolves user via getSession callback, maps optional fields,
 *   handles absent/missing id, handles errors gracefully
 * - clerkAdapter: resolves user via getUserIdFromRequest + getUser, assembles
 *   full name, picks primary email, handles missing user, handles errors at
 *   each step, exposes getUser for direct lookups
 */

import { describe, expect, it, vi } from "vitest";
import type { AuthJsOptions } from "../src/auth/adapters/authjs.js";
import { authJsAdapter } from "../src/auth/adapters/authjs.js";
import type { BetterAuthInstance } from "../src/auth/adapters/better-auth.js";
import { betterAuthAdapter } from "../src/auth/adapters/better-auth.js";
import type { ClerkAdapterOptions, ClerkUser } from "../src/auth/adapters/clerk.js";
import { clerkAdapter } from "../src/auth/adapters/clerk.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(headers: Record<string, string> = {}): Request {
	return new Request("https://example.com/api", { headers });
}

// ---------------------------------------------------------------------------
// betterAuthAdapter
// ---------------------------------------------------------------------------

describe("betterAuthAdapter", () => {
	function makeBetterAuth(
		sessionResult: Awaited<ReturnType<BetterAuthInstance["api"]["getSession"]>>,
	): BetterAuthInstance {
		return {
			api: {
				getSession: vi.fn().mockResolvedValue(sessionResult),
			},
		};
	}

	it("resolves a user when session contains a full user object", async () => {
		const auth = makeBetterAuth({
			user: {
				id: "ba-user-1",
				email: "alice@example.com",
				name: "Alice",
				image: "https://cdn.example.com/alice.png",
			},
		});
		const adapter = betterAuthAdapter(auth);
		const user = await adapter.resolveUser(makeRequest());

		expect(user).toEqual({
			id: "ba-user-1",
			email: "alice@example.com",
			name: "Alice",
			image: "https://cdn.example.com/alice.png",
		});
	});

	it("resolves a user when optional fields are absent", async () => {
		const auth = makeBetterAuth({
			user: { id: "ba-user-2", email: "bob@example.com" },
		});
		const adapter = betterAuthAdapter(auth);
		const user = await adapter.resolveUser(makeRequest());

		expect(user).toEqual({ id: "ba-user-2", email: "bob@example.com" });
		expect(user).not.toHaveProperty("name");
		expect(user).not.toHaveProperty("image");
	});

	it("passes request headers to getSession", async () => {
		const getSession = vi.fn().mockResolvedValue({
			user: { id: "ba-user-3", email: "carol@example.com" },
		});
		const auth: BetterAuthInstance = { api: { getSession } };
		const req = makeRequest({ cookie: "session=abc123" });
		await betterAuthAdapter(auth).resolveUser(req);

		expect(getSession).toHaveBeenCalledWith({ headers: req.headers });
	});

	it("returns null when getSession returns null", async () => {
		const auth = makeBetterAuth(null);
		const adapter = betterAuthAdapter(auth);
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when session has no user", async () => {
		// Cast to satisfy the narrow type – simulates a malformed response.
		const auth: BetterAuthInstance = {
			api: {
				// biome-ignore lint/suspicious/noExplicitAny: intentional malformed mock
				getSession: vi.fn().mockResolvedValue({ user: null } as any),
			},
		};
		const adapter = betterAuthAdapter(auth);
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when getSession throws", async () => {
		const auth: BetterAuthInstance = {
			api: { getSession: vi.fn().mockRejectedValue(new Error("network error")) },
		};
		const adapter = betterAuthAdapter(auth);
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});

	it("does not expose a getUser implementation", () => {
		const adapter = betterAuthAdapter(makeBetterAuth(null));
		// Optional method – absent on this adapter (better-auth has no public
		// get-user-by-id on its api object).
		expect(adapter.getUser).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// authJsAdapter
// ---------------------------------------------------------------------------

describe("authJsAdapter", () => {
	function makeAuthJsOptions(
		sessionResult: Awaited<ReturnType<AuthJsOptions["getSession"]>>,
	): AuthJsOptions {
		return { getSession: vi.fn().mockResolvedValue(sessionResult) };
	}

	it("resolves a user from a full session", async () => {
		const options = makeAuthJsOptions({
			user: {
				id: "aj-user-1",
				email: "diana@example.com",
				name: "Diana",
				image: "https://cdn.example.com/diana.png",
			},
		});
		const adapter = authJsAdapter(options);
		const user = await adapter.resolveUser(makeRequest());

		expect(user).toEqual({
			id: "aj-user-1",
			email: "diana@example.com",
			name: "Diana",
			image: "https://cdn.example.com/diana.png",
		});
	});

	it("resolves a user when optional fields are absent", async () => {
		const options = makeAuthJsOptions({ user: { id: "aj-user-2" } });
		const adapter = authJsAdapter(options);
		const user = await adapter.resolveUser(makeRequest());

		expect(user).toEqual({ id: "aj-user-2" });
		expect(user).not.toHaveProperty("email");
		expect(user).not.toHaveProperty("name");
		expect(user).not.toHaveProperty("image");
	});

	it("passes the request to getSession", async () => {
		const getSession = vi.fn().mockResolvedValue({ user: { id: "aj-user-3" } });
		const req = makeRequest({ cookie: "next-auth.session-token=xyz" });
		await authJsAdapter({ getSession }).resolveUser(req);

		expect(getSession).toHaveBeenCalledWith(req);
	});

	it("returns null when getSession returns null", async () => {
		const adapter = authJsAdapter(makeAuthJsOptions(null));
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when session has no user", async () => {
		// biome-ignore lint/suspicious/noExplicitAny: intentional malformed mock
		const options: AuthJsOptions = { getSession: vi.fn().mockResolvedValue({ user: null } as any) };
		const adapter = authJsAdapter(options);
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when user object has no id", async () => {
		// biome-ignore lint/suspicious/noExplicitAny: intentional missing-id mock
		const options: AuthJsOptions = {
			getSession: vi.fn().mockResolvedValue({ user: { email: "e@example.com" } } as any),
		};
		const adapter = authJsAdapter(options);
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when getSession throws", async () => {
		const options: AuthJsOptions = {
			getSession: vi.fn().mockRejectedValue(new Error("session store down")),
		};
		const adapter = authJsAdapter(options);
		expect(await adapter.resolveUser(makeRequest())).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// clerkAdapter
// ---------------------------------------------------------------------------

describe("clerkAdapter", () => {
	function makeClerkUser(overrides: Partial<ClerkUser> = {}): ClerkUser {
		return {
			id: "clerk-user-1",
			emailAddresses: [{ emailAddress: "eve@example.com" }],
			firstName: "Eve",
			lastName: "Smith",
			imageUrl: "https://cdn.clerk.com/eve.png",
			...overrides,
		};
	}

	function makeOptions(userId: string | null, clerkUser: ClerkUser | null): ClerkAdapterOptions {
		return {
			getUserIdFromRequest: vi.fn().mockResolvedValue(userId),
			getUser: vi.fn().mockResolvedValue(clerkUser),
		};
	}

	it("resolves a user when session and clerk user are present", async () => {
		const options = makeOptions("clerk-user-1", makeClerkUser());
		const adapter = clerkAdapter(options);
		const user = await adapter.resolveUser(makeRequest());

		expect(user).toEqual({
			id: "clerk-user-1",
			email: "eve@example.com",
			name: "Eve Smith",
			image: "https://cdn.clerk.com/eve.png",
		});
	});

	it("assembles name from firstName only when lastName is absent", async () => {
		const options = makeOptions(
			"clerk-user-2",
			makeClerkUser({ id: "clerk-user-2", lastName: null }),
		);
		const user = await clerkAdapter(options).resolveUser(makeRequest());
		expect(user?.name).toBe("Eve");
	});

	it("assembles name from lastName only when firstName is absent", async () => {
		const options = makeOptions(
			"clerk-user-3",
			makeClerkUser({ id: "clerk-user-3", firstName: null }),
		);
		const user = await clerkAdapter(options).resolveUser(makeRequest());
		expect(user?.name).toBe("Smith");
	});

	it("omits name when both firstName and lastName are absent", async () => {
		const options = makeOptions(
			"clerk-user-4",
			makeClerkUser({ id: "clerk-user-4", firstName: null, lastName: null }),
		);
		const user = await clerkAdapter(options).resolveUser(makeRequest());
		expect(user).not.toHaveProperty("name");
	});

	it("picks the first email address as the primary email", async () => {
		const clerkUser = makeClerkUser({
			emailAddresses: [
				{ emailAddress: "primary@example.com" },
				{ emailAddress: "secondary@example.com" },
			],
		});
		const options = makeOptions("clerk-user-1", clerkUser);
		const user = await clerkAdapter(options).resolveUser(makeRequest());
		expect(user?.email).toBe("primary@example.com");
	});

	it("omits email when emailAddresses is empty", async () => {
		const options = makeOptions(
			"clerk-user-5",
			makeClerkUser({ id: "clerk-user-5", emailAddresses: [] }),
		);
		const user = await clerkAdapter(options).resolveUser(makeRequest());
		expect(user).not.toHaveProperty("email");
	});

	it("omits image when imageUrl is absent", async () => {
		const options = makeOptions(
			"clerk-user-6",
			makeClerkUser({ id: "clerk-user-6", imageUrl: undefined }),
		);
		const user = await clerkAdapter(options).resolveUser(makeRequest());
		expect(user).not.toHaveProperty("image");
	});

	it("returns null when getUserIdFromRequest returns null", async () => {
		const options = makeOptions(null, makeClerkUser());
		expect(await clerkAdapter(options).resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when getUser returns null", async () => {
		const options = makeOptions("clerk-user-1", null);
		expect(await clerkAdapter(options).resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when getUserIdFromRequest throws", async () => {
		const options: ClerkAdapterOptions = {
			getUserIdFromRequest: vi.fn().mockRejectedValue(new Error("clerk SDK error")),
			getUser: vi.fn().mockResolvedValue(makeClerkUser()),
		};
		expect(await clerkAdapter(options).resolveUser(makeRequest())).toBeNull();
	});

	it("returns null when getUser throws during resolveUser", async () => {
		const options: ClerkAdapterOptions = {
			getUserIdFromRequest: vi.fn().mockResolvedValue("clerk-user-1"),
			getUser: vi.fn().mockRejectedValue(new Error("clerk API down")),
		};
		expect(await clerkAdapter(options).resolveUser(makeRequest())).toBeNull();
	});

	it("exposes a getUser method for direct user lookups", async () => {
		const options = makeOptions("clerk-user-1", makeClerkUser());
		const adapter = clerkAdapter(options);

		expect(adapter.getUser).toBeDefined();

		const user = await adapter.getUser?.("clerk-user-1");
		expect(user).toEqual({
			id: "clerk-user-1",
			email: "eve@example.com",
			name: "Eve Smith",
			image: "https://cdn.clerk.com/eve.png",
		});
	});

	it("getUser returns null when the underlying getUser throws", async () => {
		const options: ClerkAdapterOptions = {
			getUserIdFromRequest: vi.fn().mockResolvedValue("clerk-user-1"),
			getUser: vi.fn().mockRejectedValue(new Error("not found")),
		};
		const adapter = clerkAdapter(options);
		expect(await adapter.getUser?.("clerk-user-1")).toBeNull();
	});

	it("getUser returns null when getUser returns null", async () => {
		const options = makeOptions("clerk-user-1", null);
		const adapter = clerkAdapter(options);
		expect(await adapter.getUser?.("clerk-user-1")).toBeNull();
	});
});
