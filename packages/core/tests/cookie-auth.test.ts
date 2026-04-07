/**
 * Tests for the cookieAuth adapter.
 *
 * Covers:
 * - Extracts JWT from named cookie and resolves user
 * - Returns null when no cookie header present
 * - Returns null when named cookie is missing
 * - Returns null for invalid/expired JWT
 * - Custom claim mapping
 * - Extra claims passed as metadata
 */

import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { cookieAuth } from "../src/auth/adapters/cookie.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SECRET = "test-secret-that-is-at-least-1-char";
const KEY = new TextEncoder().encode(SECRET);

async function makeJwt(
	claims: Record<string, unknown>,
	opts?: { expiresIn?: string },
): Promise<string> {
	let builder = new SignJWT(claims).setProtectedHeader({ alg: "HS256" });
	if (opts?.expiresIn) {
		builder = builder.setExpirationTime(opts.expiresIn);
	} else {
		builder = builder.setExpirationTime("1h");
	}
	return builder.sign(KEY);
}

function makeRequest(cookies: Record<string, string> = {}): Request {
	const cookieStr = Object.entries(cookies)
		.map(([k, v]) => `${k}=${v}`)
		.join("; ");
	const headers: Record<string, string> = {};
	if (cookieStr) headers.cookie = cookieStr;
	return new Request("https://example.com/api", { headers });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("cookieAuth", () => {
	const adapter = cookieAuth({
		secret: SECRET,
		cookieName: "glinr_token",
	});

	it("resolves a user from a valid JWT cookie", async () => {
		const token = await makeJwt({
			user_id: "gh-123",
			email: "alice@example.com",
			name: "Alice",
			avatar: "https://cdn.example.com/alice.png",
		});
		const req = makeRequest({ glinr_token: token });
		const user = await adapter.resolveUser(req);

		expect(user).toEqual({
			id: "gh-123",
			email: "alice@example.com",
			name: "Alice",
			image: "https://cdn.example.com/alice.png",
		});
	});

	it("returns null when no cookie header is present", async () => {
		const req = new Request("https://example.com/api");
		const user = await adapter.resolveUser(req);
		expect(user).toBeNull();
	});

	it("returns null when the named cookie is missing", async () => {
		const req = makeRequest({ other_cookie: "value" });
		const user = await adapter.resolveUser(req);
		expect(user).toBeNull();
	});

	it("returns null for an invalid JWT", async () => {
		const req = makeRequest({ glinr_token: "not-a-valid-jwt" });
		const user = await adapter.resolveUser(req);
		expect(user).toBeNull();
	});

	it("returns null for a JWT signed with wrong secret", async () => {
		const wrongKey = new TextEncoder().encode("wrong-secret");
		const token = await new SignJWT({ user_id: "gh-123" })
			.setProtectedHeader({ alg: "HS256" })
			.setExpirationTime("1h")
			.sign(wrongKey);

		const req = makeRequest({ glinr_token: token });
		const user = await adapter.resolveUser(req);
		expect(user).toBeNull();
	});

	it("falls back to sub claim when user_id is absent", async () => {
		const token = await makeJwt({ sub: "sub-456" });
		const req = makeRequest({ glinr_token: token });
		const user = await adapter.resolveUser(req);

		expect(user).not.toBeNull();
		expect(user?.id).toBe("sub-456");
	});

	it("returns null when no ID claim exists", async () => {
		const token = await makeJwt({ email: "nobody@example.com" });
		const req = makeRequest({ glinr_token: token });
		const user = await adapter.resolveUser(req);
		expect(user).toBeNull();
	});

	it("collects extra claims as metadata", async () => {
		const token = await makeJwt({
			user_id: "gh-789",
			org_id: "org-42",
			role: "admin",
		});
		const req = makeRequest({ glinr_token: token });
		const user = await adapter.resolveUser(req);

		expect(user?.metadata).toEqual({
			org_id: "org-42",
			role: "admin",
		});
	});

	it("supports custom claim mapping", async () => {
		const customAdapter = cookieAuth({
			secret: SECRET,
			cookieName: "my_token",
			claimMapping: {
				id: "sub",
				email: "mail",
				name: "display_name",
				image: "photo",
			},
		});

		const token = await makeJwt({
			sub: "custom-1",
			mail: "bob@example.com",
			display_name: "Bob",
			photo: "https://cdn.example.com/bob.png",
		});
		const req = makeRequest({ my_token: token });
		const user = await customAdapter.resolveUser(req);

		expect(user).toEqual({
			id: "custom-1",
			email: "bob@example.com",
			name: "Bob",
			image: "https://cdn.example.com/bob.png",
		});
	});

	it("uses default cookie name 'token' when not specified", async () => {
		const defaultAdapter = cookieAuth({ secret: SECRET });
		const token = await makeJwt({ user_id: "default-user" });
		const req = makeRequest({ token });
		const user = await defaultAdapter.resolveUser(req);

		expect(user?.id).toBe("default-user");
	});
});
