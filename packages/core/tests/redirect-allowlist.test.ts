/** Return URL allow list: same-origin paths and exact allowed origins only. */

import { describe, expect, it } from "vitest";
import { resolveRedirectTarget, safeRedirectTarget } from "../src/redirect/allowlist.js";
import { createRedirectChain } from "../src/redirect/chain.js";

const ALLOWED = { allowedOrigins: ["https://app.example.com", "http://localhost:3000"] };

/** [candidate, accepted] */
const TABLE: Array<[string, boolean]> = [
	// Same-origin paths
	["/", true],
	["/dashboard", true],
	["/dashboard/projects/42", true],
	["/dashboard?tab=usage", true],
	["/dashboard?tab=usage#billing", true],
	["/a%20b", true],
	["/search?q=a%2Fb", true],
	["/search?next=//evil.com", true],
	["/@user", true],
	["/path/with/unicode/%C3%A9", true],
	["/./dashboard", true],
	["/x/../y", true],
	// Protocol-relative and slash variants
	["//evil.com", false],
	["//evil.com/path", false],
	["///evil.com", false],
	["////evil.com", false],
	["/\\evil.com", false],
	["\\\\evil.com", false],
	["\\/evil.com", false],
	["/\\/evil.com", false],
	["/.//evil.com", false],
	["/..//evil.com", false],
	// Encoded variants
	["/%2Fevil.com", false],
	["/%2F%2Fevil.com", false],
	["/%5Cevil.com", false],
	["/%5cevil.com", false],
	["/%252F%252Fevil.com", false],
	["/%25%32%46%25%32%46evil.com", false],
	["/%0A/evil.com", false],
	["/%09/evil.com", false],
	["/%0D%0Aevil", false],
	["/%00", false],
	["%2F%2Fevil.com", false],
	["%5C%5Cevil.com", false],
	["/%E2%80%A8//evil.com", false],
	// Control characters and whitespace
	["/\t/evil.com", false],
	["/\n/evil.com", false],
	["/\r/evil.com", false],
	["\t//evil.com", false],
	[" //evil.com", false],
	[" /dashboard", false],
	["/dashboard ", false],
	["/da shboard", false],
	["/\u0000evil", false],
	["/ /evil.com", false],
	["/ /evil.com", false],
	["/﻿/evil.com", false],
	// Dangerous schemes
	["javascript:alert(1)", false],
	["JaVaScRiPt:alert(1)", false],
	["javascript://%0Aalert(1)", false],
	["data:text/html,<script>alert(1)</script>", false],
	["data:text/html;base64,PHNjcmlwdD4=", false],
	["vbscript:msgbox(1)", false],
	["file:///etc/passwd", false],
	["ftp://app.example.com/", false],
	["blob:https://app.example.com/uuid", false],
	["about:blank", false],
	["myapp://callback", false],
	// Absolute URLs against the allow list
	["https://app.example.com", true],
	["https://app.example.com/", true],
	["https://app.example.com/dashboard?x=1#y", true],
	["HTTPS://APP.EXAMPLE.COM/dashboard", true],
	["http://localhost:3000/cb", true],
	["https://evil.com", false],
	["https://evil.com/https://app.example.com", false],
	["http://app.example.com", false],
	["https://app.example.com:8443/", false],
	["https://app.example.com.evil.com/", false],
	["https://evil-app.example.com/", false],
	["https://sub.app.example.com/", false],
	["https://app.example.com@evil.com/", false],
	["https://evil.com@app.example.com/", false],
	["https://user:pass@app.example.com/", false],
	["https://app.example.com:pw@evil.com/", false],
	["https://app.example.com\\@evil.com/", false],
	["https://app.example.com\\.evil.com/", false],
	["https:evil.com", false],
	["https:/evil.com", false],
	["https:\\\\evil.com", false],
	["https://", false],
	["http:///app.example.com", false],
	["https://app.example.com%2F@evil.com/", false],
	["https://app.example.com%40evil.com/", false],
	// Not paths
	["evil.com", false],
	["dashboard", false],
	["www.evil.com/path", false],
	["?next=/", false],
	["#frag", false],
	["", false],
];

describe("resolveRedirectTarget table", () => {
	it("has at least 60 candidates", () => {
		expect(TABLE.length).toBeGreaterThanOrEqual(60);
	});

	for (const [candidate, accepted] of TABLE) {
		it(`${accepted ? "accepts" : "rejects"} ${JSON.stringify(candidate)}`, () => {
			const result = resolveRedirectTarget(candidate, ALLOWED);
			if (accepted) expect(result).not.toBeNull();
			else expect(result).toBeNull();
		});
	}
});

describe("resolveRedirectTarget details", () => {
	it("rejects non strings and oversize input", () => {
		for (const v of [null, undefined, 42, {}, ["/x"], true]) {
			expect(resolveRedirectTarget(v, ALLOWED)).toBeNull();
		}
		expect(resolveRedirectTarget(`/${"a".repeat(3000)}`, ALLOWED)).toBeNull();
	});

	it("rejects every absolute URL when no origin is allow listed", () => {
		expect(resolveRedirectTarget("https://app.example.com/x")).toBeNull();
		expect(resolveRedirectTarget("/x")).toBe("/x");
	});

	it("ignores allow list entries that are not bare http(s) origins", () => {
		const o = {
			allowedOrigins: ["javascript:alert(1)", "https://a.com/path", "*.b.com", "not a url"],
		};
		expect(resolveRedirectTarget("https://a.com/path", o)).toBeNull();
		expect(resolveRedirectTarget("javascript:alert(1)", o)).toBeNull();
	});

	it("returns normalised absolute URLs", () => {
		expect(resolveRedirectTarget("HTTPS://APP.EXAMPLE.COM/x", ALLOWED)).toBe(
			"https://app.example.com/x",
		);
	});

	it("safeRedirectTarget falls back", () => {
		expect(safeRedirectTarget("//evil.com", ALLOWED)).toBe("/");
		expect(safeRedirectTarget("//evil.com", ALLOWED, "/home")).toBe("/home");
		expect(safeRedirectTarget("/ok", ALLOWED)).toBe("/ok");
	});
});

describe("redirect chain integration", () => {
	function forgedCookie(path: string): string {
		const state = {
			origin: { id: "x", path, query: {}, hash: "", createdAt: Date.now() },
			steps: [],
			createdAt: Date.now(),
		};
		return btoa(JSON.stringify(state)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}
	const withCookie = (v: string): Request =>
		new Request("http://localhost/cb", { headers: { cookie: `theauth_redirect=${v}` } });

	it("a forged cookie path //evil.com pops as the default path", () => {
		const chain = createRedirectChain({ defaultPath: "/home" });
		const popped = chain.pop(withCookie(forgedCookie("//evil.com")));
		expect(popped.url).toBe("/home");
		expect(chain.peek(withCookie(forgedCookie("/\\evil.com")))?.url).toBe("/home");
	});

	it("a request path starting with // is not captured as a destination", () => {
		const chain = createRedirectChain();
		const setCookie = chain.capture(new Request("http://localhost//evil.com/x"));
		const value = (setCookie.split(";")[0] ?? "").split("=")[1] ?? "";
		expect(chain.pop(withCookie(value)).url).toBe("/");
	});

	it("pushed steps are checked when built", () => {
		const chain = createRedirectChain();
		chain.push(new Request("http://localhost/"), "//evil.com");
		const entry = chain.createEntry("//evil.com");
		expect(chain.buildUrl(entry)).toBe("/");
	});

	it("sanitize accepts allow listed origins and rejects others", () => {
		const chain = createRedirectChain({ allowedOrigins: ["https://app.example.com"] });
		expect(chain.sanitize("https://app.example.com/x")).toBe("https://app.example.com/x");
		expect(chain.sanitize("https://evil.com/x")).toBe("/");
		expect(chain.sanitize("/ok?x=1")).toBe("/ok?x=1");
		expect(chain.sanitize("javascript:alert(1)")).toBe("/");
	});

	it("normal destinations still round trip", () => {
		const chain = createRedirectChain();
		const setCookie = chain.capture(new Request("http://localhost/dashboard?tab=usage#billing"));
		const value = (setCookie.split(";")[0] ?? "").split("=")[1] ?? "";
		expect(chain.pop(withCookie(value)).url).toBe("/dashboard?tab=usage#billing");
	});
});
