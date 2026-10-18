import { describe, expect, it } from "vitest";
import { parseError, parseSession } from "../src/wire.js";

describe("parseSession", () => {
	it("reads the core sign-in body", () => {
		expect(
			parseSession({
				user: { id: "u1", username: "ada@example.com" },
				session: { token: "tok", expiresAt: "2030-01-01T00:00:00Z" },
			}),
		).toEqual({
			token: "tok",
			user: { id: "u1", email: "ada@example.com", name: undefined, image: undefined },
			expiresAt: "2030-01-01T00:00:00Z",
		});
	});

	it("keeps the held token for GET /auth/session, which has none", () => {
		const s = parseSession({ user: { id: "u1" }, session: { id: "s1" } }, "held");
		expect(s?.token).toBe("held");
		expect(parseSession({ user: { id: "u1" }, session: { id: "s1" } })).toBeNull();
	});

	it("still reads the data envelope", () => {
		expect(parseSession({ data: { token: "t", user: { id: "u" } } })?.token).toBe("t");
	});

	it("rejects a body without a user", () => {
		expect(parseSession({ session: { token: "t" } })).toBeNull();
		expect(parseSession(null)).toBeNull();
	});
});

describe("parseError", () => {
	it("reads string and object errors", () => {
		expect(parseError({ error: "Invalid username or password" }, "x")).toBe(
			"Invalid username or password",
		);
		expect(parseError({ error: { message: "nope" } }, "x")).toBe("nope");
		expect(parseError({}, "fallback")).toBe("fallback");
	});
});
