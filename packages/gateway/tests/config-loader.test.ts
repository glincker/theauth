import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfigFile, resolveTrustedProxy } from "../src/config-loader.js";

let dir: string;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "gateway-config-"));
});

afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

function write(config: unknown): string {
	const path = join(dir, "gateway.json");
	writeFileSync(path, JSON.stringify(config));
	return path;
}

describe("loadConfigFile trustedProxy", () => {
	it("defaults to no trustedProxy (trust nothing)", () => {
		const config = loadConfigFile(write({ upstream: "http://localhost:8080" }));
		expect(config.trustedProxy).toBeUndefined();
	});

	it("accepts trustedProxyCount", () => {
		const config = loadConfigFile(
			write({ upstream: "http://localhost:8080", trustedProxy: { trustedProxyCount: 1 } }),
		);
		expect(config.trustedProxy).toEqual({ trustedProxyCount: 1 });
	});

	it("accepts zero as an explicit count", () => {
		const config = loadConfigFile(
			write({ upstream: "http://localhost:8080", trustedProxy: { trustedProxyCount: 0 } }),
		);
		expect(config.trustedProxy).toEqual({ trustedProxyCount: 0 });
	});

	it("lowercases trustedHeader", () => {
		const config = loadConfigFile(
			write({
				upstream: "http://localhost:8080",
				trustedProxy: { trustedHeader: "CF-Connecting-IP" },
			}),
		);
		expect(config.trustedProxy).toEqual({ trustedHeader: "cf-connecting-ip" });
	});

	it("rejects a negative count", () => {
		expect(() =>
			loadConfigFile(
				write({ upstream: "http://localhost:8080", trustedProxy: { trustedProxyCount: -1 } }),
			),
		).toThrow(/trustedProxy\.trustedProxyCount/);
	});

	it("rejects a fractional count", () => {
		expect(() =>
			loadConfigFile(
				write({ upstream: "http://localhost:8080", trustedProxy: { trustedProxyCount: 1.5 } }),
			),
		).toThrow(/trustedProxy\.trustedProxyCount/);
	});

	it("rejects a non number count", () => {
		expect(() =>
			loadConfigFile(
				write({ upstream: "http://localhost:8080", trustedProxy: { trustedProxyCount: "1" } }),
			),
		).toThrow(/trustedProxy\.trustedProxyCount/);
	});

	it("rejects an empty or malformed header name", () => {
		for (const trustedHeader of ["", "   ", "bad header", "x:y"]) {
			expect(() =>
				loadConfigFile(
					write({ upstream: "http://localhost:8080", trustedProxy: { trustedHeader } }),
				),
			).toThrow(/trustedProxy\.trustedHeader/);
		}
	});

	it("rejects unknown keys so a typo cannot leave the gateway trusting nothing", () => {
		expect(() =>
			loadConfigFile(
				write({ upstream: "http://localhost:8080", trustedProxy: { trustedProxyCout: 1 } }),
			),
		).toThrow(/trustedProxy/);
	});
});

describe("resolveTrustedProxy", () => {
	it("returns undefined when nothing is configured", () => {
		expect(resolveTrustedProxy(undefined)).toBeUndefined();
		expect(resolveTrustedProxy(undefined, {})).toBeUndefined();
	});

	it("passes the file value through", () => {
		expect(resolveTrustedProxy({ trustedProxyCount: 2 })).toEqual({ trustedProxyCount: 2 });
	});

	it("lets flags override the file per key", () => {
		expect(
			resolveTrustedProxy({ trustedProxyCount: 2, trustedHeader: "x-real-ip" }, { count: "1" }),
		).toEqual({ trustedProxyCount: 1, trustedHeader: "x-real-ip" });
	});

	it("parses and lowercases flag values", () => {
		expect(resolveTrustedProxy(undefined, { count: "1", header: "CF-Connecting-IP" })).toEqual({
			trustedProxyCount: 1,
			trustedHeader: "cf-connecting-ip",
		});
	});

	it("rejects a non numeric or negative count flag", () => {
		for (const count of ["abc", "-1", "1.5", ""]) {
			expect(() => resolveTrustedProxy(undefined, { count })).toThrow(/--trusted-proxy-count/);
		}
	});

	it("rejects an invalid header flag", () => {
		expect(() => resolveTrustedProxy(undefined, { header: "not a header" })).toThrow(
			/trustedHeader/,
		);
	});
});
