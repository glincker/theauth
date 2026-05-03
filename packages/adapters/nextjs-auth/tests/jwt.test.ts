import { describe, expect, it } from "vitest";
import { isTokenExpiring, readJwtExp } from "../src/jwt.js";

// Helper: build a minimal JWT with a given payload (no real signing)
function makeJwt(payload: Record<string, unknown>): string {
	const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
		.replace(/=/g, "")
		.replace(/\+/g, "-")
		.replace(/\//g, "_");
	const body = btoa(JSON.stringify(payload))
		.replace(/=/g, "")
		.replace(/\+/g, "-")
		.replace(/\//g, "_");
	return `${header}.${body}.fakesignature`;
}

describe("readJwtExp", () => {
	it("returns the exp claim from a valid JWT", () => {
		const exp = Math.floor(Date.now() / 1000) + 3600;
		const token = makeJwt({ sub: "user-1", exp });
		expect(readJwtExp(token)).toBe(exp);
	});

	it("returns null for a malformed JWT (not 3 parts)", () => {
		expect(readJwtExp("not.a.jwt.here.extra")).toBeNull();
		expect(readJwtExp("onlyone")).toBeNull();
		expect(readJwtExp("two.parts")).toBeNull();
	});

	it("returns null for a JWT without an exp claim", () => {
		const token = makeJwt({ sub: "user-1" });
		expect(readJwtExp(token)).toBeNull();
	});

	it("returns null when the payload is not valid JSON", () => {
		// Corrupt the payload section
		const token = "header.!!!notbase64!!.sig";
		expect(readJwtExp(token)).toBeNull();
	});

	it("returns null when exp is not a number", () => {
		const token = makeJwt({ sub: "user-1", exp: "not-a-number" });
		expect(readJwtExp(token)).toBeNull();
	});
});

describe("isTokenExpiring", () => {
	it("returns true when exp is within bufferS from now", () => {
		const exp = Math.floor(Date.now() / 1000) + 30; // expires in 30s
		const token = makeJwt({ exp });
		expect(isTokenExpiring(token, 60)).toBe(true); // buffer = 60s
	});

	it("returns true for an already-expired token", () => {
		const exp = Math.floor(Date.now() / 1000) - 100; // expired 100s ago
		const token = makeJwt({ exp });
		expect(isTokenExpiring(token, 60)).toBe(true);
	});

	it("returns false when exp is comfortably in the future", () => {
		const exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour away
		const token = makeJwt({ exp });
		expect(isTokenExpiring(token, 60)).toBe(false);
	});

	it("returns false for tokens with no exp claim (let backend reject)", () => {
		const token = makeJwt({ sub: "user-1" });
		expect(isTokenExpiring(token, 60)).toBe(false);
	});
});
