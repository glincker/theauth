/**
 * Regression for the HTTP review: the rateLimit() plugin must limit the endpoints core really
 * ships, and every spelling of a path must share one counter.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { rateLimit, resolveRateLimit } from "../src/auth/rate-limit.js";
import { normalizeRatePath } from "../src/auth/rate-limit-routes.js";

const hit = async (p: ReturnType<typeof rateLimit>, path: string, ip = "6.6.6.6") =>
	p.hooks?.onRequest?.(
		new Request(`http://app${path}`, {
			method: "POST",
			headers: { "cf-connecting-ip": ip, "content-type": "application/json" },
			body: "{}",
		}),
	);

const status = (r: unknown) => (r instanceof Response ? r.status : undefined);

describe("rateLimit maps the real credential routes", () => {
	it("signIn applies to /auth/username/sign-in", async () => {
		const p = rateLimit({ signIn: { window: "15m", max: 2 }, trustedHeader: "cf-connecting-ip" });
		await hit(p, "/auth/username/sign-in");
		await hit(p, "/auth/username/sign-in");
		expect(status(await hit(p, "/auth/username/sign-in"))).toBe(429);
	});

	it("passwordReset applies to /auth/forgot-password and its OTP variant", async () => {
		const p = rateLimit({
			passwordReset: { window: "1h", max: 1 },
			trustedHeader: "cf-connecting-ip",
		});
		await hit(p, "/auth/forgot-password");
		expect(status(await hit(p, "/auth/forgot-password"))).toBe(429);
		await hit(p, "/auth/forgot-password/otp");
		expect(status(await hit(p, "/auth/forgot-password/otp"))).toBe(429);
	});

	it("unconfigured credential routes still get a built-in limit", async () => {
		const p = rateLimit({ trustedHeader: "cf-connecting-ip" });
		let last: unknown;
		for (let i = 0; i < 12; i++) last = await hit(p, "/api/theauth/auth/magic-link/send");
		expect(status(last)).toBe(429);
	});

	it("`false` turns a key off", () => {
		expect(resolveRateLimit("/auth/username/sign-in", { signIn: false })).toBeUndefined();
	});
});

describe("rateLimit normalizes the path before keying", () => {
	it.each([
		"/api/theauth//mcp/token",
		"/api/theauth/mcp/token/",
		"/api/theauth/MCP/Token",
		"/api/theauth/mcp%2Ftoken",
		"/api/theauth/mcp%252Ftoken",
		"/api/theauth/%6dcp/token",
	])("%s shares the /mcp/token counter", async (spelling) => {
		const p = rateLimit({ mcpToken: { window: "1m", max: 1 }, trustedHeader: "cf-connecting-ip" });
		await hit(p, "/api/theauth/mcp/token");
		expect(status(await hit(p, "/api/theauth/mcp/token"))).toBe(429);
		expect(status(await hit(p, spelling))).toBe(429);
	});

	it("collapses, trims and lowercases", () => {
		expect(normalizeRatePath("//Auth///Username/Sign-In//")).toBe("/auth/username/sign-in");
		expect(normalizeRatePath("/")).toBe("/");
		expect(normalizeRatePath("/auth/%zz")).toBe("/auth/%zz");
	});
});

/** Every `/auth/...` path literal under src/auth, which is where core registers its routes. */
function shippedAuthPaths(): string[] {
	const dir = join(__dirname, "../src/auth");
	const paths = new Set<string>();
	for (const name of readdirSync(dir)) {
		if (!name.endsWith(".ts") || name.startsWith("rate-limit")) continue;
		const text = readFileSync(join(dir, name), "utf8");
		for (const match of text.matchAll(/["'`](\/auth\/[a-z0-9/_:-]+)["'`]/g)) {
			if (match[1]) paths.add(match[1]);
		}
	}
	return [...paths].sort();
}

/** A route that takes a password, a code, a one time token or creates an account. */
const CREDENTIAL =
	/(sign-in|sign-up|password|\/otp\/|otp\/(send|verify)$|\/code\/|send-code|magic-link\/(send|verify)|passkey\/(authenticate|login)\/verify|siwe\/verify|one-tap\/callback|\/anonymous(\/upgrade)?$|2fa\/(verify|enable|disable|backup-codes)|phone\/verify|verify-email\/(send|confirm)|mobile\/exchange|device\/(code|token|authorize)|agent\/authorize)/;

describe("every shipped credential route has a specific limit", () => {
	const credentialPaths = shippedAuthPaths().filter((p) => CREDENTIAL.test(p));

	it("finds the credential routes", () => {
		expect(credentialPaths).toContain("/auth/username/sign-in");
		expect(credentialPaths).toContain("/auth/forgot-password");
		expect(credentialPaths.length).toBeGreaterThan(25);
	});

	it.each(credentialPaths)("%s resolves to a non-default limit", (path) => {
		const sentinel = { window: "1m", max: 999_999 };
		const limit = resolveRateLimit(`/api/theauth${path}`, { default: sentinel });
		expect(limit).toBeDefined();
		expect(limit).not.toBe(sentinel);
	});
});
