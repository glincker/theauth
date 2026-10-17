/** Tests for the Have I Been Pwned password checking module. */

import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHibpModule, HibpApiError, HibpBreachedError } from "../src/auth/hibp.js";

function sha1Upper(input: string): string {
	return createHash("sha1").update(input, "utf8").digest("hex").toUpperCase();
}

/** Build a fake HIBP range response body where the given password appears `count` times, plus a handful of unrelated suffixes. */
function buildRangeBody(password: string, count: number): string {
	const hash = sha1Upper(password);
	const suffix = hash.slice(5);

	const lines: string[] = [
		`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3`,
		`BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:1`,
		`${suffix}:${count}`,
		`CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:7`,
	];

	return lines.join("\r\n");
}

function mockFetch(body: string, status = 200): void {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue({
			ok: status >= 200 && status < 300,
			status,
			text: () => Promise.resolve(body),
		}),
	);
}

function mockFetchError(error: Error): void {
	vi.stubGlobal("fetch", vi.fn().mockRejectedValue(error));
}

describe("createHibpModule", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	describe("check()", () => {
		it("returns breach count for a compromised password", async () => {
			const password = "password123";
			mockFetch(buildRangeBody(password, 42));

			const hibp = createHibpModule();
			const count = await hibp.check(password);

			expect(count).toBe(42);
		});

		it("returns 0 for a clean password (suffix not in response)", async () => {
			// Give the API a body that doesn't include our password's suffix
			mockFetch(
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:1\r\n",
			);

			const hibp = createHibpModule();
			const count = await hibp.check("a-very-unique-correct-horse-battery-staple-99xzy");

			expect(count).toBe(0);
		});

		it("only sends the 5-char prefix to the API (k-anonymity)", async () => {
			const password = "test-password";
			const hash = sha1Upper(password);
			const expectedPrefix = hash.slice(0, 5);

			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				text: () => Promise.resolve(buildRangeBody(password, 1)),
			});
			vi.stubGlobal("fetch", fetchMock);

			const hibp = createHibpModule();
			await hibp.check(password);

			const calledUrl: string = (fetchMock.mock.calls[0] as [string])[0];
			expect(calledUrl).toContain(expectedPrefix);
			// The full hash must NOT appear in the URL
			expect(calledUrl).not.toContain(hash);
		});

		it("uses the custom apiUrl when provided", async () => {
			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				text: () => Promise.resolve(""),
			});
			vi.stubGlobal("fetch", fetchMock);

			const hibp = createHibpModule({ apiUrl: "https://hibp.example.com" });
			await hibp.check("anything");

			const calledUrl: string = (fetchMock.mock.calls[0] as [string])[0];
			expect(calledUrl).toMatch(/^https:\/\/hibp\.example\.com\/range\//);
		});
	});

	describe("enforce()", () => {
		it("throws HibpBreachedError when password is breached (threshold=0)", async () => {
			const password = "hunter2";
			mockFetch(buildRangeBody(password, 100));

			const hibp = createHibpModule({ threshold: 0 });
			await expect(hibp.enforce(password)).rejects.toThrow(HibpBreachedError);
		});

		it("does not throw for a clean password", async () => {
			mockFetch("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3\r\n");

			const hibp = createHibpModule();
			await expect(
				hibp.enforce("a-very-unique-correct-horse-battery-staple-99xzy"),
			).resolves.toBeUndefined();
		});

		it("respects a custom threshold", async () => {
			const password = "common-password";
			// 5 breaches, below threshold of 10, should pass
			mockFetch(buildRangeBody(password, 5));

			const hibp = createHibpModule({ threshold: 10 });
			await expect(hibp.enforce(password)).resolves.toBeUndefined();

			// 15 breaches, above threshold, should throw
			mockFetch(buildRangeBody(password, 15));
			await expect(hibp.enforce(password)).rejects.toThrow(HibpBreachedError);
		});

		it("HibpBreachedError carries the breach count", async () => {
			const password = "123456";
			mockFetch(buildRangeBody(password, 999));

			const hibp = createHibpModule();
			try {
				await hibp.enforce(password);
				expect.fail("Should have thrown");
			} catch (err) {
				expect(err).toBeInstanceOf(HibpBreachedError);
				expect((err as HibpBreachedError).count).toBe(999);
			}
		});
	});

	describe("API error handling", () => {
		it("returns 0 on network error when onError is 'allow' (default)", async () => {
			mockFetchError(new Error("Network failure"));

			const hibp = createHibpModule({ onError: "allow" });
			const count = await hibp.check("any-password");
			expect(count).toBe(0);
		});

		it("returns 0 on timeout when onError is 'allow'", async () => {
			// AbortSignal.timeout fires a DOMException-like error
			const abortError = new DOMException("The operation was aborted", "AbortError");
			mockFetchError(abortError);

			const hibp = createHibpModule({ onError: "allow", timeoutMs: 1 });
			const count = await hibp.check("any-password");
			expect(count).toBe(0);
		});

		it("throws HibpApiError on network error when onError is 'block'", async () => {
			mockFetchError(new Error("Connection refused"));

			const hibp = createHibpModule({ onError: "block" });
			await expect(hibp.check("any-password")).rejects.toThrow(HibpApiError);
		});

		it("throws HibpApiError on HTTP error when onError is 'block'", async () => {
			mockFetch("Service Unavailable", 503);

			const hibp = createHibpModule({ onError: "block" });
			await expect(hibp.check("any-password")).rejects.toThrow(HibpApiError);
		});

		it("returns 0 on HTTP error when onError is 'allow'", async () => {
			mockFetch("Too Many Requests", 429);

			const hibp = createHibpModule({ onError: "allow" });
			const count = await hibp.check("any-password");
			expect(count).toBe(0);
		});
	});

	// SHA-1 prefix / suffix matching

	describe("SHA-1 prefix/suffix matching", () => {
		it("correctly identifies the password in the range response", async () => {
			const password = "correct-horse-battery-staple";
			const hash = sha1Upper(password);
			const prefix = hash.slice(0, 5);
			const suffix = hash.slice(5);

			// Build a response where our suffix appears exactly once
			const body = [
				`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:10`,
				`${suffix}:1`,
				`ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:5`,
			].join("\n");

			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				text: () => Promise.resolve(body),
			});
			vi.stubGlobal("fetch", fetchMock);

			const hibp = createHibpModule();
			const count = await hibp.check(password);

			// Verify the correct prefix was sent
			const calledUrl: string = (fetchMock.mock.calls[0] as [string])[0];
			expect(calledUrl.endsWith(prefix)).toBe(true);

			// Verify the correct count was returned
			expect(count).toBe(1);
		});

		it("handles case-insensitive suffix matching", async () => {
			const password = "mixed-case-test";
			const hash = sha1Upper(password);
			const suffix = hash.slice(5);

			const body = `${suffix.toLowerCase()}:3\n`;

			mockFetch(body);

			const hibp = createHibpModule();
			const count = await hibp.check(password);
			expect(count).toBe(3);
		});
	});
});
