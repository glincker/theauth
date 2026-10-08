import { describe, expect, it } from "vitest";
import { resolveClientIp } from "../src/auth/client-ip.js";
import { rateLimit } from "../src/auth/rate-limit.js";
import { memoryStorage } from "../src/storage/index.js";
import { createTheAuth } from "../src/theauth.js";

const hit = (plugin: ReturnType<typeof rateLimit>, req: Request) => plugin.hooks?.onRequest?.(req);
const req = (path: string, headers: Record<string, string> = {}, body?: string) =>
	new Request(`http://localhost${path}`, { method: "POST", headers, body });

describe("resolveClientIp", () => {
	it("ignores forwarded headers by default", () => {
		expect(
			resolveClientIp(req("/", { "x-forwarded-for": "1.1.1.1", "x-real-ip": "2.2.2.2" })),
		).toBeNull();
	});
	it("takes the entry the nearest trusted proxy appended", () => {
		const r = req("/", { "x-forwarded-for": "6.6.6.6, 1.1.1.1, 2.2.2.2" });
		expect(resolveClientIp(r, { trustedProxyCount: 1 })).toBe("2.2.2.2");
		expect(resolveClientIp(r, { trustedProxyCount: 2 })).toBe("1.1.1.1");
	});
	it("a spoofed leading value cannot pick the key", () => {
		const a = req("/", { "x-forwarded-for": "9.9.9.9, 3.3.3.3" });
		const b = req("/", { "x-forwarded-for": "8.8.8.8, 3.3.3.3" });
		expect(resolveClientIp(a, { trustedProxyCount: 1 })).toBe(
			resolveClientIp(b, { trustedProxyCount: 1 }),
		);
	});
	it("uses a single trusted header and rejects junk values", () => {
		expect(
			resolveClientIp(req("/", { "cf-connecting-ip": "4.4.4.4" }), {
				trustedHeader: "cf-connecting-ip",
			}),
		).toBe("4.4.4.4");
		expect(
			resolveClientIp(req("/", { "cf-connecting-ip": "a b;c" }), {
				trustedHeader: "cf-connecting-ip",
			}),
		).toBeNull();
	});
});

describe("rateLimit key safety", () => {
	it("rotating x-forwarded-for does not escape the limit by default", async () => {
		const p = rateLimit({ signIn: { window: "1m", max: 2 } });
		await hit(p, req("/auth/sign-in", { "x-forwarded-for": "1.1.1.1" }));
		await hit(p, req("/auth/sign-in", { "x-forwarded-for": "2.2.2.2" }));
		const third = await hit(p, req("/auth/sign-in", { "x-forwarded-for": "3.3.3.3" }));
		expect((third as Response).status).toBe(429);
	});
	it("with trustedHeader, different clients get separate buckets", async () => {
		const p = rateLimit({ signIn: { window: "1m", max: 1 }, trustedHeader: "cf-connecting-ip" });
		await hit(p, req("/auth/sign-in", { "cf-connecting-ip": "1.1.1.1" }));
		expect(await hit(p, req("/auth/sign-in", { "cf-connecting-ip": "2.2.2.2" }))).toBeUndefined();
		expect(
			((await hit(p, req("/auth/sign-in", { "cf-connecting-ip": "1.1.1.1" }))) as Response).status,
		).toBe(429);
	});
});

describe("mcp and device endpoints", () => {
	it("limits /mcp/token and /mcp/register by default", async () => {
		const p = rateLimit({
			mcpToken: { window: "1m", max: 1 },
			mcpRegister: { window: "1m", max: 1 },
		});
		for (const path of ["/mcp/token", "/mcp/register"]) {
			expect(await hit(p, req(path))).toBeUndefined();
			expect(((await hit(p, req(path))) as Response).status).toBe(429);
		}
	});
	it("has built-in limits for device endpoints and can be disabled with false", async () => {
		const on = rateLimit({});
		let blocked = false;
		for (let i = 0; i < 12; i++) {
			const r = await hit(on, req("/auth/device/code"));
			if (r instanceof Response) blocked = true;
		}
		expect(blocked).toBe(true);
		const off = rateLimit({ deviceCode: false });
		for (let i = 0; i < 50; i++) expect(await hit(off, req("/auth/device/code"))).toBeUndefined();
	});
	it("does not touch unrelated paths", async () => {
		expect(
			await hit(rateLimit({ default: { window: "1m", max: 1 } }), req("/other")),
		).toBeUndefined();
	});
});

describe("per client_id key", () => {
	it("keys on client_id from a form body regardless of IP", async () => {
		const p = rateLimit({
			mcpToken: { window: "1m", max: 1 },
			keyBy: "client_id",
			trustedProxyCount: 1,
		});
		const call = (id: string, ip: string) =>
			hit(
				p,
				req(
					"/mcp/token",
					{ "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": ip },
					`client_id=${id}&grant_type=x`,
				),
			);
		expect(await call("app-a", "1.1.1.1")).toBeUndefined();
		expect(((await call("app-a", "2.2.2.2")) as Response).status).toBe(429);
		expect(await call("app-b", "1.1.1.1")).toBeUndefined();
	});
	it("reads JSON bodies and Basic auth, falls back to ip", async () => {
		const p = rateLimit({ mcpToken: { window: "1m", max: 1 }, keyBy: "client_id" });
		expect(
			await hit(
				p,
				req(
					"/mcp/token",
					{ "content-type": "application/json" },
					JSON.stringify({ client_id: "j" }),
				),
			),
		).toBeUndefined();
		expect(
			(
				(await hit(
					p,
					req(
						"/mcp/token",
						{ "content-type": "application/json" },
						JSON.stringify({ client_id: "j" }),
					),
				)) as Response
			).status,
		).toBe(429);
		const basic = { authorization: `Basic ${btoa("cli:secret")}` };
		expect(await hit(p, req("/mcp/token", basic))).toBeUndefined();
		expect(((await hit(p, req("/mcp/token", basic))) as Response).status).toBe(429);
	});
});

describe("store wiring", () => {
	it("accepts a SecondaryStorage as store", async () => {
		const storage = memoryStorage();
		const p = rateLimit({ signIn: { window: "1m", max: 1 }, store: storage });
		await hit(p, req("/auth/sign-in"));
		expect(((await hit(p, req("/auth/sign-in"))) as Response).status).toBe(429);
	});
	it("follows createTheAuth secondaryStorage.rateLimit and runRequestHooks enforces it", async () => {
		const storage = memoryStorage();
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			secondaryStorage: { rateLimit: storage },
			plugins: [rateLimit({ mcpToken: { window: "1m", max: 1 } })],
		});
		expect(await auth.plugins.runRequestHooks(req("/mcp/token"))).toBeInstanceOf(Request);
		const blocked = await auth.plugins.runRequestHooks(req("/mcp/token"));
		expect(blocked).toBeInstanceOf(Response);
		expect(await storage.list?.("theauth:rateLimit:")).toHaveLength(1);
	});
});
