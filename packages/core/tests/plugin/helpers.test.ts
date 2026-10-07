import { describe, expect, it } from "vitest";
import {
	buildClearCookie,
	buildSetCookie,
	extractToken,
	getCookie,
	json,
	parseBody,
} from "../../src/plugin/helpers.js";

describe("json", () => {
	it("returns a Response with JSON content type", async () => {
		const res = json({ ok: true });
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("application/json");
		const body = await res.json();
		expect(body).toEqual({ ok: true });
	});

	it("respects custom status", () => {
		const res = json({ error: "bad" }, 400);
		expect(res.status).toBe(400);
	});
});

describe("parseBody", () => {
	it("parses valid JSON", async () => {
		const req = new Request("http://localhost", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "test@example.com" }),
		});
		const result = await parseBody(req);
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.data.email).toBe("test@example.com");
	});

	it("returns error response for invalid JSON", async () => {
		const req = new Request("http://localhost", {
			method: "POST",
			body: "not json",
		});
		const result = await parseBody(req);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.response.status).toBe(400);
			const body = await result.response.json();
			expect(body.error).toBe("Invalid JSON body");
		}
	});
});

describe("getCookie", () => {
	it("extracts named cookie", () => {
		const req = new Request("http://localhost", {
			headers: { cookie: "theauth_session=abc123; other=xyz" },
		});
		expect(getCookie(req, "theauth_session")).toBe("abc123");
	});

	it("returns null when cookie missing", () => {
		const req = new Request("http://localhost");
		expect(getCookie(req, "theauth_session")).toBeNull();
	});

	it("returns null when no cookie header", () => {
		const req = new Request("http://localhost");
		expect(getCookie(req, "anything")).toBeNull();
	});
});

describe("extractToken", () => {
	it("prefers Authorization header", () => {
		const req = new Request("http://localhost", {
			headers: {
				authorization: "Bearer my-token",
				cookie: "theauth_session=cookie-token",
			},
		});
		expect(extractToken(req)).toBe("my-token");
	});

	it("falls back to cookie", () => {
		const req = new Request("http://localhost", {
			headers: { cookie: "theauth_session=cookie-token" },
		});
		expect(extractToken(req)).toBe("cookie-token");
	});

	it("returns null when neither exists", () => {
		const req = new Request("http://localhost");
		expect(extractToken(req)).toBeNull();
	});

	it("uses custom cookie name", () => {
		const req = new Request("http://localhost", {
			headers: { cookie: "my_cookie=tok123" },
		});
		expect(extractToken(req, "my_cookie")).toBe("tok123");
	});
});

describe("buildSetCookie", () => {
	it("builds a valid Set-Cookie string", () => {
		const cookie = buildSetCookie("theauth_session", "tok123", 86400);
		expect(cookie).toContain("theauth_session=tok123");
		expect(cookie).toContain("HttpOnly");
		expect(cookie).toContain("Secure");
		expect(cookie).toContain("SameSite=Lax");
		expect(cookie).toContain("Max-Age=86400");
		expect(cookie).toContain("Path=/");
	});
});

describe("buildClearCookie", () => {
	it("builds a cookie-clearing string", () => {
		const cookie = buildClearCookie("theauth_session");
		expect(cookie).toContain("Max-Age=0");
		expect(cookie).toContain("theauth_session=");
	});
});
