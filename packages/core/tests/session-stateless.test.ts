/** Stateless (database-less) sessions: signed identity cookie, encrypted token cookie, chunking, refresh single flight and tamper resistance. */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { StatelessIdentity, StatelessTokens } from "../src/session/stateless.js";
import { createStatelessSessions } from "../src/session/stateless.js";

const SECRET = "stateless-test-secret-that-is-at-least-32-chars";
const IDENTITY: StatelessIdentity = { sub: "idp|42", email: "a@example.com", sid: "sid-1" };

/** Request Cookie header from Set-Cookie headers, skipping deletions. */
function cookieHeader(setCookies: string[]): string {
	const pairs = new Map<string, string>();
	for (const header of setCookies) {
		const [pair] = header.split(";") as [string];
		const eq = pair.indexOf("=");
		const name = pair.slice(0, eq);
		const value = pair.slice(eq + 1);
		if (/Max-Age=0/i.test(header) || value === "") pairs.delete(name);
		else pairs.set(name, value);
	}
	return [...pairs].map(([k, v]) => `${k}=${v}`).join("; ");
}

function mutateCookie(header: string, name: string, fn: (value: string) => string): string {
	return header
		.split("; ")
		.map((p) => {
			const eq = p.indexOf("=");
			return p.slice(0, eq) === name ? `${name}=${fn(p.slice(eq + 1))}` : p;
		})
		.join("; ");
}

function expectSuccess<T>(r: { success: boolean } & Record<string, unknown>): T {
	if (!r.success) throw new Error(JSON.stringify(r.error));
	return r.data as T;
}

afterEach(() => {
	vi.useRealTimers();
});

describe("stateless sessions", () => {
	it("round trips identity and tokens through cookies", async () => {
		const s = createStatelessSessions({ secret: SECRET });
		const created = expectSuccess<{ headers: string[] }>(
			await s.createSession(IDENTITY, { accessToken: "at-1", refreshToken: "rt-1" }),
		);
		const header = cookieHeader(created.headers);

		const session = await s.getSession(header);
		expect(session?.identity).toEqual(IDENTITY);

		const token = expectSuccess<{ accessToken: string; headers: string[] }>(
			await s.getAccessToken(header),
		);
		expect(token.accessToken).toBe("at-1");
		expect(token.headers).toEqual([]);
	});

	it("keeps IdP tokens encrypted in the browser", async () => {
		const s = createStatelessSessions({ secret: SECRET });
		const created = expectSuccess<{ headers: string[] }>(
			await s.createSession(IDENTITY, { accessToken: "super-secret-access", refreshToken: "rt-x" }),
		);
		const tokenCookie = created.headers.find((h) => h.startsWith("theauth_stateless_tokens"));
		expect(tokenCookie).toBeDefined();
		const raw = decodeURIComponent(tokenCookie ?? "");
		expect(raw).not.toContain("super-secret-access");
		expect(raw).not.toContain(btoa("super-secret-access").replace(/=+$/, ""));
	});

	it("rejects a session signed with another secret", async () => {
		const a = createStatelessSessions({ secret: SECRET });
		const b = createStatelessSessions({ secret: `${SECRET}-other` });
		const created = expectSuccess<{ headers: string[] }>(
			await a.createSession(IDENTITY, { accessToken: "at" }),
		);
		const header = cookieHeader(created.headers);
		expect(await b.getSession(header)).toBeNull();
		const r = await b.getAccessToken(header);
		expect(r.success).toBe(false);
	});

	describe("tamper rejection", () => {
		async function issued() {
			const s = createStatelessSessions({ secret: SECRET });
			const created = expectSuccess<{ headers: string[] }>(
				await s.createSession(IDENTITY, { accessToken: "at", refreshToken: "rt" }),
			);
			return { s, header: cookieHeader(created.headers) };
		}

		it("rejects an edited identity payload", async () => {
			const { s, header } = await issued();
			const forged = btoa(
				JSON.stringify({ identity: { sub: "admin" }, expiresAt: Date.now() + 1e6 }),
			)
				.replace(/\+/g, "-")
				.replace(/\//g, "_")
				.replace(/=+$/, "");
			const bad = mutateCookie(header, "theauth_stateless", (v) => `${forged}.${v.split(".")[1]}`);
			expect(await s.getSession(bad)).toBeNull();
		});

		it("rejects a flipped signature", async () => {
			const { s, header } = await issued();
			// Flip a character well inside the signature. The last base64url character of a 32 byte MAC carries
			// only 4 significant bits, so swapping it can decode to the same bytes and be rightly accepted.
			const bad = mutateCookie(header, "theauth_stateless", (v) => {
				const at = v.length - 8;
				return v.slice(0, at) + (v[at] === "A" ? "B" : "A") + v.slice(at + 1);
			});
			expect(await s.getSession(bad)).toBeNull();
		});

		it("rejects a tampered token ciphertext", async () => {
			const { s, header } = await issued();
			const bad = mutateCookie(header, "theauth_stateless_tokens", (v) => {
				const [iv, ct] = v.split(".") as [string, string];
				const mid = Math.floor(ct.length / 2);
				const swapped = ct[mid] === "A" ? "B" : "A";
				return `${iv}.${ct.slice(0, mid)}${swapped}${ct.slice(mid + 1)}`;
			});
			const r = await s.getAccessToken(bad);
			expect(r.success).toBe(false);
			if (!r.success) expect(r.error.code).toBe("NO_TOKENS");
		});

		it("rejects a token cookie moved onto a session it does not belong to", async () => {
			const { s, header } = await issued();
			const other = createStatelessSessions({ secret: `${SECRET}-2` });
			const foreign = expectSuccess<{ headers: string[] }>(
				await other.createSession({ sub: "someone-else" }, { accessToken: "stolen" }),
			);
			const foreignTokens = cookieHeader(foreign.headers)
				.split("; ")
				.find((p) => p.startsWith("theauth_stateless_tokens="));
			const mixed = mutateCookie(
				header,
				"theauth_stateless_tokens",
				() => foreignTokens?.split("=").slice(1).join("=") ?? "",
			);
			const r = await s.getAccessToken(mixed);
			expect(r.success).toBe(false);
		});

		it("rejects an expired session", async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date("2026-10-12T00:00:00Z"));
			const s = createStatelessSessions({ secret: SECRET, maxAge: 60 });
			const created = expectSuccess<{ headers: string[] }>(
				await s.createSession(IDENTITY, { accessToken: "at" }),
			);
			const header = cookieHeader(created.headers);
			expect(await s.getSession(header)).not.toBeNull();
			vi.setSystemTime(new Date("2026-10-12T00:02:00Z"));
			expect(await s.getSession(header)).toBeNull();
		});

		it("honors isRevoked", async () => {
			const s = createStatelessSessions({
				secret: SECRET,
				isRevoked: async (id) => id.sid === "sid-1",
			});
			const created = expectSuccess<{ headers: string[] }>(await s.createSession(IDENTITY));
			expect(await s.getSession(cookieHeader(created.headers))).toBeNull();
		});
	});

	describe("cookie chunking", () => {
		const big = { note: "x".repeat(5000) };

		it("splits a large identity across chunks and reads it back", async () => {
			const s = createStatelessSessions({ secret: SECRET });
			const created = expectSuccess<{ headers: string[] }>(
				await s.createSession({ ...IDENTITY, claims: big }, { accessToken: "at" }),
			);
			const names = created.headers.map((h) => h.split("=")[0]);
			expect(names).toContain("theauth_stateless.0");
			expect(names).toContain("theauth_stateless.1");
			expect(names).not.toContain("theauth_stateless");
			for (const h of created.headers)
				expect((h.split(";")[0] ?? "").length).toBeLessThanOrEqual(4096);

			const session = await s.getSession(cookieHeader(created.headers));
			expect(session?.identity.claims).toEqual(big);
		});

		it("keeps a small value in a single cookie", async () => {
			const s = createStatelessSessions({ secret: SECRET });
			const created = expectSuccess<{ headers: string[] }>(await s.createSession(IDENTITY));
			expect(created.headers.map((h) => h.split("=")[0])).toEqual(["theauth_stateless"]);
		});

		it("fails with COOKIE_TOO_LARGE past maxChunks", async () => {
			const s = createStatelessSessions({ secret: SECRET, chunking: { maxChunks: 1 } });
			const r = await s.createSession({ ...IDENTITY, claims: big });
			expect(r.success).toBe(false);
			if (!r.success) expect(r.error.code).toBe("COOKIE_TOO_LARGE");
		});

		it("deletes stale chunks when a smaller value replaces a chunked one", async () => {
			const s = createStatelessSessions({ secret: SECRET });
			const first = expectSuccess<{ headers: string[] }>(
				await s.createSession({ ...IDENTITY, claims: big }),
			);
			const header = cookieHeader(first.headers);
			const second = expectSuccess<{ headers: string[] }>(
				await s.createSession(IDENTITY, undefined, header),
			);
			const deletions = second.headers.filter((h) => /Max-Age=0/i.test(h));
			expect(deletions.some((h) => h.startsWith("theauth_stateless.0="))).toBe(true);
			expect(deletions.some((h) => h.startsWith("theauth_stateless.1="))).toBe(true);
		});

		it("clear() deletes the identity and token cookies and their chunks", async () => {
			const s = createStatelessSessions({ secret: SECRET });
			const created = expectSuccess<{ headers: string[] }>(
				await s.createSession({ ...IDENTITY, claims: big }, { accessToken: "at" }),
			);
			const cleared = s.clear(cookieHeader(created.headers));
			expect(cleared.every((h) => /Max-Age=0/i.test(h))).toBe(true);
			const names = cleared.map((h) => h.split("=")[0]);
			expect(names).toEqual(
				expect.arrayContaining(["theauth_stateless.0", "theauth_stateless_tokens"]),
			);
		});
	});

	describe("refresh", () => {
		const expired: StatelessTokens = {
			accessToken: "old-at",
			refreshToken: "rt-1",
			expiresAt: Date.now() - 1000,
		};

		async function withExpired(refresh: (rt: string) => Promise<unknown>) {
			const s = createStatelessSessions({
				secret: SECRET,
				refreshAccessToken: refresh as never,
			});
			const created = expectSuccess<{ headers: string[] }>(
				await s.createSession(IDENTITY, expired),
			);
			return { s, header: cookieHeader(created.headers) };
		}

		it("invokes the refresh callback once for concurrent callers", async () => {
			let calls = 0;
			const { s, header } = await withExpired(async (rt) => {
				calls++;
				await new Promise((r) => setTimeout(r, 20));
				return {
					success: true,
					data: {
						accessToken: "new-at",
						refreshToken: `${rt}-next`,
						expiresAt: Date.now() + 3600_000,
					},
				};
			});
			const results = await Promise.all(Array.from({ length: 10 }, () => s.getAccessToken(header)));
			expect(calls).toBe(1);
			for (const r of results) {
				const data = expectSuccess<{ accessToken: string; headers: string[] }>(r);
				expect(data.accessToken).toBe("new-at");
				expect(data.headers.length).toBeGreaterThan(0);
			}
		});

		it("re-seals rotated tokens so the next request needs no refresh", async () => {
			let calls = 0;
			const { s, header } = await withExpired(async () => {
				calls++;
				return {
					success: true,
					data: { accessToken: "new-at", refreshToken: "rt-2", expiresAt: Date.now() + 3600_000 },
				};
			});
			const first = expectSuccess<{ headers: string[] }>(await s.getAccessToken(header));
			// The browser keeps the newest cookie; mirror that by replacing the token cookie.
			const merged = mutateCookie(
				header,
				"theauth_stateless_tokens",
				() =>
					cookieHeader(first.headers)
						.split("; ")
						.find((p) => p.startsWith("theauth_stateless_tokens="))
						?.split("=")
						.slice(1)
						.join("=") ?? "",
			);
			const second = expectSuccess<{ accessToken: string; headers: string[] }>(
				await s.getAccessToken(merged),
			);
			expect(second.accessToken).toBe("new-at");
			expect(second.headers).toEqual([]);
			expect(calls).toBe(1);
		});

		it("keeps the old refresh token when the IdP does not rotate it", async () => {
			const seen: string[] = [];
			const { s, header } = await withExpired(async (rt) => {
				seen.push(rt);
				return { success: true, data: { accessToken: "a2", expiresAt: Date.now() - 1 } };
			});
			expectSuccess(await s.getAccessToken(header));
			const first = expectSuccess<{ headers: string[] }>(await s.getAccessToken(header));
			const merged = mutateCookie(
				header,
				"theauth_stateless_tokens",
				() =>
					cookieHeader(first.headers)
						.split("; ")
						.find((p) => p.startsWith("theauth_stateless_tokens="))
						?.split("=")
						.slice(1)
						.join("=") ?? "",
			);
			expectSuccess(await s.getAccessToken(merged));
			expect(seen).toEqual(["rt-1", "rt-1", "rt-1"]);
		});

		it("propagates a refresh failure and retries on the next call", async () => {
			let calls = 0;
			const { s, header } = await withExpired(async () => {
				calls++;
				return calls === 1
					? { success: false, error: { code: "IDP_DOWN", message: "down" } }
					: { success: true, data: { accessToken: "ok", expiresAt: Date.now() + 1e6 } };
			});
			const r1 = await s.getAccessToken(header);
			expect(r1.success).toBe(false);
			if (!r1.success) expect(r1.error.code).toBe("IDP_DOWN");
			expect((await s.getAccessToken(header)).success).toBe(true);
			expect(calls).toBe(2);
		});

		it("fails with ACCESS_TOKEN_EXPIRED when there is nothing to refresh with", async () => {
			const s = createStatelessSessions({ secret: SECRET });
			const created = expectSuccess<{ headers: string[] }>(
				await s.createSession(IDENTITY, { accessToken: "a", expiresAt: Date.now() - 1 }),
			);
			const r = await s.getAccessToken(cookieHeader(created.headers));
			expect(r.success).toBe(false);
			if (!r.success) expect(r.error.code).toBe("ACCESS_TOKEN_EXPIRED");
		});
	});
});
