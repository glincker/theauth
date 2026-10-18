/** failClosed options: a backing store or API error denies when asked to, and the default stays fail open with a startup warning. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createAdapterAdmission } from "../src/adapter-admit.js";
import { createHibpModule, HibpApiError } from "../src/auth/hibp.js";
import { rateLimit } from "../src/auth/rate-limit.js";
import type { RateLimitStore } from "../src/auth/stores/types.js";
import type { SecondaryStorage } from "../src/storage/types.js";

afterEach(() => vi.unstubAllGlobals());

const proxy = { trustedHeader: "x-real-ip" };
const boom = async (): Promise<never> => {
	throw new Error("store down");
};
const brokenStorage: SecondaryStorage = { get: boom, set: boom, delete: boom, incr: boom };
const brokenStore: RateLimitStore = { increment: boom, reset: boom };

function signIn(): Request {
	return new Request("https://api.example.com/auth/sign-in", {
		method: "POST",
		headers: { "x-real-ip": "1.1.1.1" },
	});
}

describe("adapter admission failClosed", () => {
	it("admits on a store error by default and warns once at startup", async () => {
		const warn = vi.fn();
		const a = createAdapterAdmission({ logger: { warn } }, proxy, brokenStorage);
		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn.mock.calls[0]?.[0]).toMatch(/fails open/);
		expect(warn.mock.calls[0]?.[0]).toMatch(/sign-in and sign-up/);
		expect(await a.admit(signIn(), "/sign-in")).toBeNull();
	});

	it("denies with 503 on a store error when failClosed is true", async () => {
		const warn = vi.fn();
		const a = createAdapterAdmission(
			{ rateLimit: { failClosed: true }, logger: { warn } },
			proxy,
			brokenStorage,
		);
		expect(warn).not.toHaveBeenCalled();
		const denied = await a.admit(signIn(), "/sign-in");
		expect(denied?.status).toBe(503);
		expect(denied?.headers.get("retry-after")).toBe("5");
	});

	it("does not warn when there is no shared store (in-process limiter cannot fail)", () => {
		const warn = vi.fn();
		createAdapterAdmission({ logger: { warn } }, proxy);
		expect(warn).not.toHaveBeenCalled();
	});
});

describe("rateLimit plugin failClosed", () => {
	async function run(failClosed: boolean | undefined, warn = vi.fn()) {
		const plugin = rateLimit({
			signIn: { window: "1m", max: 5 },
			store: brokenStore,
			failClosed,
			logger: { warn },
		});
		const result = await plugin.hooks?.onRequest?.(signIn());
		return { result, warn };
	}

	it("lets the request through by default and warns", async () => {
		const { result, warn } = await run(undefined);
		expect(result).toBeUndefined();
		expect(warn.mock.calls.map((c) => c[0]).join("|")).toMatch(/fails open/);
	});

	it("returns 503 when failClosed is true", async () => {
		const { result } = await run(true);
		expect((result as Response).status).toBe(503);
	});
});

describe("hibp failClosed", () => {
	it("blocks with HibpApiError when failClosed is true", async () => {
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network")));
		const hibp = createHibpModule({ failClosed: true });
		await expect(hibp.check("password123")).rejects.toBeInstanceOf(HibpApiError);
		await expect(hibp.enforce("password123")).rejects.toBeInstanceOf(HibpApiError);
	});

	it("blocks on an HTTP 503 too", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue({ ok: false, status: 503, text: async () => "" }),
		);
		await expect(
			createHibpModule({ failClosed: true }).check("password123"),
		).rejects.toBeInstanceOf(HibpApiError);
	});

	it("fails open by default and warns at startup", async () => {
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network")));
		const warn = vi.fn();
		const hibp = createHibpModule({ logger: { warn } });
		expect(warn.mock.calls[0]?.[0]).toMatch(/fails open/);
		expect(await hibp.check("password123")).toBe(0);
	});

	it("failClosed wins over onError allow and silences the warning", async () => {
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network")));
		const warn = vi.fn();
		const hibp = createHibpModule({ failClosed: true, onError: "allow", logger: { warn } });
		expect(warn).not.toHaveBeenCalled();
		await expect(hibp.check("password123")).rejects.toBeInstanceOf(HibpApiError);
	});
});
