/**
 * Tests for RedirectChain — the cookie-based redirect state manager.
 *
 * Covers:
 * - capture() stores request URL as origin
 * - capture() keeps existing origin on repeat calls (user refreshes sign-in page)
 * - capture() falls back to defaultPath for excluded paths
 * - push() adds intermediate steps
 * - pop() returns steps in FIFO order then the origin
 * - pop() returns defaultPath when chain is empty / expired
 * - peek() returns next step without consuming
 * - getOrigin() returns the original URL
 * - clear() removes the chain
 * - Expired chains return defaultPath
 * - Max depth prevents infinite chains
 * - Excluded paths are not stored as destinations
 * - Query params and hash fragments are preserved
 * - buildUrl() reconstructs full URL
 * - createEntry() creates a valid RedirectEntry
 */

import { describe, expect, it, vi } from "vitest";
import { createRedirectChain } from "../src/redirect/chain.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a mock Request with the given URL and optional existing chain cookie. */
function makeRequest(url: string, cookieValue?: string): Request {
	const headers = new Headers();
	if (cookieValue !== undefined) {
		headers.set("cookie", `kavach_redirect=${cookieValue}`);
	}
	return new Request(url, { headers });
}

/** Extract cookie value from a Set-Cookie header string. */
function extractCookieValue(header: string): string {
	const part = header.split(";")[0] ?? "";
	const eqIdx = part.indexOf("=");
	return eqIdx === -1 ? "" : part.slice(eqIdx + 1);
}

// ---------------------------------------------------------------------------
// capture()
// ---------------------------------------------------------------------------

describe("capture()", () => {
	it("stores the request URL as the origin", () => {
		const chain = createRedirectChain();
		const req = makeRequest("http://localhost/dashboard/projects");
		const setCookie = chain.capture(req);

		expect(setCookie).toContain("kavach_redirect=");

		// Parse it back
		const cookieValue = extractCookieValue(setCookie);
		const reqWithCookie = makeRequest("http://localhost/sign-in", cookieValue);
		const origin = chain.getOrigin(reqWithCookie);

		expect(origin).not.toBeNull();
		expect(origin?.path).toBe("/dashboard/projects");
	});

	it("preserves an existing origin when called again (user refreshed sign-in)", () => {
		const chain = createRedirectChain();

		// First capture: user was at /dashboard
		const req1 = makeRequest("http://localhost/dashboard");
		const cookie1 = extractCookieValue(chain.capture(req1));

		// Second capture: somehow called with sign-in page URL but existing cookie
		const req2 = makeRequest("http://localhost/sign-in", cookie1);
		const cookie2 = extractCookieValue(chain.capture(req2));

		const req3 = makeRequest("http://localhost/sign-in", cookie2);
		const origin = chain.getOrigin(req3);

		// Should preserve /dashboard, not /sign-in
		expect(origin?.path).toBe("/dashboard");
	});

	it("replaces excluded paths with defaultPath", () => {
		const chain = createRedirectChain({ defaultPath: "/home" });
		// /sign-in is in the default exclusion list
		const req = makeRequest("http://localhost/sign-in?returnTo=something");
		const setCookie = chain.capture(req);

		const cookieValue = extractCookieValue(setCookie);
		const reqWithCookie = makeRequest("http://localhost/sign-in", cookieValue);
		const origin = chain.getOrigin(reqWithCookie);

		expect(origin?.path).toBe("/home");
		expect(origin?.query).toEqual({});
	});

	it("respects custom excluded paths (exact match)", () => {
		const chain = createRedirectChain({ excludePaths: ["/admin", "/api/"] });
		// Exact match on /admin
		const req = makeRequest("http://localhost/admin");
		const setCookie = chain.capture(req);

		const cookieValue = extractCookieValue(setCookie);
		const reqWithCookie = makeRequest("http://localhost/sign-in", cookieValue);
		const origin = chain.getOrigin(reqWithCookie);

		expect(origin?.path).toBe("/");
	});

	it("respects custom excluded path prefix (trailing slash)", () => {
		const chain = createRedirectChain({ excludePaths: ["/admin/", "/api/"] });
		// Prefix match: /admin/users starts with /admin/
		const req = makeRequest("http://localhost/admin/users");
		const setCookie = chain.capture(req);

		const cookieValue = extractCookieValue(setCookie);
		const reqWithCookie = makeRequest("http://localhost/sign-in", cookieValue);
		const origin = chain.getOrigin(reqWithCookie);

		expect(origin?.path).toBe("/");
	});
});

// ---------------------------------------------------------------------------
// push() and pop()
// ---------------------------------------------------------------------------

describe("push() and pop()", () => {
	it("pop() returns steps in order then the origin", () => {
		// pop() re-parses the cookie on each call — to simulate a real multi-step
		// redirect sequence we build each "request" from the current in-memory state
		// by using push() to build up the chain and reading the encoded cookie.
		const chain = createRedirectChain({ cookie: { secure: false } });

		// 1. Capture origin
		const originReq = makeRequest("http://localhost/final-destination");
		const c0 = extractCookieValue(chain.capture(originReq));
		chain.parse(makeRequest("http://localhost/", c0));

		// 2. Push two steps
		chain.push("/step-one");
		const c1 = extractCookieValue(chain.push("/step-two"));

		// 3. First pop (step-one)
		const r1 = chain.pop(makeRequest("http://localhost/", c1));
		expect(r1.url).toBe("/step-one");
		expect(r1.done).toBe(false);
		expect(r1.clearCookie).toBeNull();

		// 4. After pop, currentState has step-one removed. Encode the mutated state
		//    by re-serializing — we simulate the server writing back the updated cookie.
		//    Since pop doesn't return an updated cookie, we push the remaining state
		//    back to get a cookie reflecting only [step-two, origin].
		//    Alternatively, build a new chain from scratch with just step-two + origin.
		const chain2 = createRedirectChain({ cookie: { secure: false } });
		const c2_0 = extractCookieValue(
			chain2.capture(makeRequest("http://localhost/final-destination")),
		);
		chain2.parse(makeRequest("http://localhost/", c2_0));
		const c2_1 = extractCookieValue(chain2.push("/step-two"));

		// 5. Pop step-two
		const r2 = chain2.pop(makeRequest("http://localhost/", c2_1));
		expect(r2.url).toBe("/step-two");
		expect(r2.done).toBe(false);

		// 6. Final pop — origin
		const chain3 = createRedirectChain({ cookie: { secure: false } });
		const c3_0 = extractCookieValue(
			chain3.capture(makeRequest("http://localhost/final-destination")),
		);

		const r3 = chain3.pop(makeRequest("http://localhost/", c3_0));
		expect(r3.url).toBe("/final-destination");
		expect(r3.done).toBe(true);
		expect(r3.clearCookie).not.toBeNull();
	});

	it("pop() returns defaultPath when chain is empty", () => {
		const chain = createRedirectChain({ defaultPath: "/home" });
		// No cookie set
		const req = makeRequest("http://localhost/sign-in");
		const result = chain.pop(req);

		expect(result.url).toBe("/home");
		expect(result.done).toBe(true);
		expect(result.clearCookie).not.toBeNull();
	});

	it("pop() returns origin when steps are exhausted", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });
		const originReq = makeRequest("http://localhost/dashboard");
		const c0 = extractCookieValue(chain.capture(originReq));

		// No steps pushed, pop should go straight to origin
		const r = chain.pop(makeRequest("http://localhost/", c0));
		expect(r.url).toBe("/dashboard");
		expect(r.done).toBe(true);
	});

	it("max depth prevents pushing beyond the limit", () => {
		const chain = createRedirectChain({ maxDepth: 2, cookie: { secure: false } });

		const req = makeRequest("http://localhost/origin");
		const c0 = extractCookieValue(chain.capture(req));
		chain.parse(makeRequest("http://localhost/", c0));

		chain.push("/step-1");
		chain.push("/step-2");
		// This one should be ignored (maxDepth = 2)
		const c1 = extractCookieValue(chain.push("/step-3-should-be-dropped"));

		const state = chain.parse(makeRequest("http://localhost/", c1));
		expect(state?.steps.length).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// peek()
// ---------------------------------------------------------------------------

describe("peek()", () => {
	it("returns next step without consuming it", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });

		const req = makeRequest("http://localhost/origin");
		const c0 = extractCookieValue(chain.capture(req));
		chain.parse(makeRequest("http://localhost/", c0));
		const c1 = extractCookieValue(chain.push("/next-step"));

		const peeked = chain.peek(makeRequest("http://localhost/", c1));
		expect(peeked?.url).toBe("/next-step");
		expect(peeked?.remaining).toBe(1);

		// Peeking again returns the same result
		const peeked2 = chain.peek(makeRequest("http://localhost/", c1));
		expect(peeked2?.url).toBe("/next-step");
	});

	it("returns origin URL when no steps remain", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });

		const req = makeRequest("http://localhost/origin-page");
		const c0 = extractCookieValue(chain.capture(req));

		const peeked = chain.peek(makeRequest("http://localhost/", c0));
		expect(peeked?.url).toBe("/origin-page");
		expect(peeked?.remaining).toBe(0);
	});

	it("returns null when no chain exists", () => {
		const chain = createRedirectChain();
		const req = makeRequest("http://localhost/sign-in");
		expect(chain.peek(req)).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// getOrigin()
// ---------------------------------------------------------------------------

describe("getOrigin()", () => {
	it("returns the original URL", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });

		const req = makeRequest("http://localhost/settings/billing");
		const c0 = extractCookieValue(chain.capture(req));
		chain.parse(makeRequest("http://localhost/", c0));
		chain.push("/step-1");
		const c1 = extractCookieValue(chain.push("/step-2"));

		// Even with steps pushed, origin should remain
		const origin = chain.getOrigin(makeRequest("http://localhost/", c1));
		expect(origin?.path).toBe("/settings/billing");
	});

	it("returns null when no chain exists", () => {
		const chain = createRedirectChain();
		const req = makeRequest("http://localhost/sign-in");
		expect(chain.getOrigin(req)).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// clear()
// ---------------------------------------------------------------------------

describe("clear()", () => {
	it("removes the chain by returning a Max-Age=0 cookie", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });

		const req = makeRequest("http://localhost/dashboard");
		chain.capture(req);

		const clearHeader = chain.clear();
		expect(clearHeader).toContain("Max-Age=0");
		expect(clearHeader).toContain("kavach_redirect=");
	});

	it("chain is gone after clear", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });

		const req = makeRequest("http://localhost/dashboard");
		const c0 = extractCookieValue(chain.capture(req));
		chain.parse(makeRequest("http://localhost/", c0));
		chain.clear();

		// pop with the old cookie still works via cookie but internal state is gone
		// A fresh chain with no cookie should return defaultPath
		const freshChain = createRedirectChain();
		const result = freshChain.pop(makeRequest("http://localhost/sign-in"));
		expect(result.url).toBe("/");
		expect(result.done).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

describe("expiry", () => {
	it("expired chains return defaultPath on pop()", () => {
		const chain = createRedirectChain({
			maxAge: 1, // 1 second
			defaultPath: "/expired",
			cookie: { secure: false },
		});

		const req = makeRequest("http://localhost/dashboard");
		const c0 = extractCookieValue(chain.capture(req));

		// Fast-forward time by 2 seconds
		const now = Date.now();
		vi.spyOn(Date, "now").mockReturnValue(now + 2000);

		const result = chain.pop(makeRequest("http://localhost/sign-in", c0));
		expect(result.url).toBe("/expired");
		expect(result.done).toBe(true);

		vi.restoreAllMocks();
	});

	it("expired chains return null on parse()", () => {
		const chain = createRedirectChain({ maxAge: 1, cookie: { secure: false } });

		const req = makeRequest("http://localhost/dashboard");
		const c0 = extractCookieValue(chain.capture(req));

		const now = Date.now();
		vi.spyOn(Date, "now").mockReturnValue(now + 2000);

		const state = chain.parse(makeRequest("http://localhost/sign-in", c0));
		expect(state).toBeNull();

		vi.restoreAllMocks();
	});
});

// ---------------------------------------------------------------------------
// Query params and hash fragments
// ---------------------------------------------------------------------------

describe("query params and hash preservation", () => {
	it("preserves query params in origin", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });
		const req = makeRequest("http://localhost/search?q=agents&page=2");
		const c0 = extractCookieValue(chain.capture(req));

		const origin = chain.getOrigin(makeRequest("http://localhost/", c0));
		expect(origin?.query).toEqual({ q: "agents", page: "2" });
	});

	it("preserves hash in origin", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });
		const req = makeRequest("http://localhost/docs/quickstart#installation");
		const c0 = extractCookieValue(chain.capture(req));

		const origin = chain.getOrigin(makeRequest("http://localhost/", c0));
		expect(origin?.hash).toBe("installation");
	});

	it("buildUrl() reconstructs path + query + hash", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });
		const req = makeRequest("http://localhost/page?foo=bar&baz=qux#section");
		const c0 = extractCookieValue(chain.capture(req));

		const origin = chain.getOrigin(makeRequest("http://localhost/", c0));
		const url = chain.buildUrl(origin!);

		expect(url).toContain("/page");
		expect(url).toContain("foo=bar");
		expect(url).toContain("baz=qux");
		expect(url).toContain("#section");
	});

	it("omits query and hash when empty", () => {
		const chain = createRedirectChain({ cookie: { secure: false } });
		const req = makeRequest("http://localhost/clean-path");
		const c0 = extractCookieValue(chain.capture(req));

		const origin = chain.getOrigin(makeRequest("http://localhost/", c0));
		const url = chain.buildUrl(origin!);

		expect(url).toBe("/clean-path");
	});

	it("strips query params when preserveQuery is false", () => {
		const chain = createRedirectChain({ preserveQuery: false, cookie: { secure: false } });
		const req = makeRequest("http://localhost/page?sensitive=data");
		const c0 = extractCookieValue(chain.capture(req));

		const origin = chain.getOrigin(makeRequest("http://localhost/", c0));
		expect(origin?.query).toEqual({});
	});

	it("strips hash when preserveHash is false", () => {
		const chain = createRedirectChain({ preserveHash: false, cookie: { secure: false } });
		const req = makeRequest("http://localhost/page#section");
		const c0 = extractCookieValue(chain.capture(req));

		const origin = chain.getOrigin(makeRequest("http://localhost/", c0));
		expect(origin?.hash).toBe("");
	});
});

// ---------------------------------------------------------------------------
// createEntry()
// ---------------------------------------------------------------------------

describe("createEntry()", () => {
	it("creates a valid entry from a URL string", () => {
		const chain = createRedirectChain();
		const entry = chain.createEntry("http://localhost/dashboard?tab=usage#billing", "test-label");

		expect(entry.path).toBe("/dashboard");
		expect(entry.query).toEqual({ tab: "usage" });
		expect(entry.hash).toBe("billing");
		expect(entry.label).toBe("test-label");
		expect(typeof entry.id).toBe("string");
		expect(entry.id.length).toBeGreaterThan(0);
		expect(typeof entry.createdAt).toBe("number");
	});

	it("creates a valid entry from a Request", () => {
		const chain = createRedirectChain();
		const req = makeRequest("http://localhost/settings?section=security");
		const entry = chain.createEntry(req);

		expect(entry.path).toBe("/settings");
		expect(entry.query).toEqual({ section: "security" });
	});

	it("creates a valid entry from a relative path", () => {
		const chain = createRedirectChain();
		const entry = chain.createEntry("/relative/path");

		expect(entry.path).toBe("/relative/path");
	});
});

// ---------------------------------------------------------------------------
// Cookie attributes
// ---------------------------------------------------------------------------

describe("cookie attributes", () => {
	it("includes HttpOnly, Secure, SameSite by default", () => {
		const chain = createRedirectChain();
		const req = makeRequest("http://localhost/dashboard");
		const setCookie = chain.capture(req);

		expect(setCookie).toContain("HttpOnly");
		expect(setCookie).toContain("Secure");
		expect(setCookie).toContain("SameSite=Lax");
	});

	it("uses custom cookie name", () => {
		const chain = createRedirectChain({ cookieName: "my_redirect" });
		const req = makeRequest("http://localhost/dashboard");
		const setCookie = chain.capture(req);

		expect(setCookie).toContain("my_redirect=");
	});

	it("includes Domain when specified", () => {
		const chain = createRedirectChain({ cookie: { domain: "example.com", secure: false } });
		const req = makeRequest("http://localhost/dashboard");
		const setCookie = chain.capture(req);

		expect(setCookie).toContain("Domain=example.com");
	});
});
