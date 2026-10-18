/**
 * Runtimes without `process` (Cloudflare Workers, Deno without node compat): a revoke must still be
 * pushed and must still clear the local cache. Plus a guard that no new bare `process` access
 * appears in src outside an allowlist.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRevocationBus, revocationRowExpiry } from "../src/mcp/revocation-bus.js";
import type {
	McpRevocationEntry,
	McpRevocationEvent,
	McpRevocationStore,
} from "../src/mcp/revocation-types.js";
import type { TheAuthLogger } from "../src/observability/types.js";
import { getEnv } from "../src/runtime/env.js";

afterEach(() => {
	vi.unstubAllGlobals();
});

function fakeStore(
	fail = false,
): McpRevocationStore & { rows: McpRevocationEntry[]; order: string[] } {
	const s = {
		rows: [] as McpRevocationEntry[],
		order: [] as string[],
		async revoke() {},
		async isRevoked() {
			return false;
		},
		async revokeMany(entries: McpRevocationEntry[]) {
			s.order.push("push");
			if (fail) throw new Error("db down");
			s.rows.push(...entries);
		},
		async check() {
			return null;
		},
		async fingerprint() {
			return "0";
		},
		async prune() {
			return 0;
		},
	};
	return s;
}

const event = (): McpRevocationEvent => ({
	kind: "sub",
	ids: ["u1"],
	revokedAt: new Date(),
	reason: "session.revokeAll",
});

describe("revocation bus without a process global", () => {
	it("getEnv returns undefined instead of throwing", () => {
		vi.stubGlobal("process", undefined);
		expect(getEnv("THEAUTH_MCP_REVOCATION_RETENTION_MS")).toBeUndefined();
	});

	it("still computes a row expiry, pushes the row and clears the local cache", async () => {
		const store = fakeStore();
		const bus = createRevocationBus({ store, retryDelayMs: 0 });
		const cleared: string[] = [];
		bus.subscribeClear?.((e) => cleared.push(e.kind));
		vi.stubGlobal("process", undefined);
		const now = new Date();
		const expiresAt = revocationRowExpiry(undefined, now);
		expect(expiresAt.getTime()).toBeGreaterThan(now.getTime());
		await bus.publish(event(), [{ kind: "sub", id: "u1", expiresAt, reason: "session.revokeAll" }]);
		vi.unstubAllGlobals();
		expect(store.rows.map((r) => r.id)).toEqual(["u1"]);
		expect(cleared.length).toBeGreaterThanOrEqual(1);
		expect(bus.stats().pushFailures).toBe(0);
	});

	it("clears the local cache BEFORE the push, and a failed push is loud and counted", async () => {
		const store = fakeStore(true);
		const warn = vi.fn();
		const error = vi.fn();
		const logger = { warn, error, info: vi.fn(), debug: vi.fn() } as unknown as TheAuthLogger;
		const bus = createRevocationBus({ store, logger, retryDelayMs: 0 });
		bus.subscribeClear?.(() => store.order.push("clear"));
		await bus.publish(event(), [
			{ kind: "sub", id: "u1", expiresAt: new Date(Date.now() + 60_000), reason: "x" },
		]);
		expect(store.order[0]).toBe("clear");
		expect(warn).toHaveBeenCalled();
		expect(error).toHaveBeenCalled();
		const stats = bus.stats();
		expect(stats.pushFailures).toBe(1);
		expect(stats.attemptFailures).toBe(2);
	});
});

const SRC = join(__dirname, "..", "src");

/** Files that may touch `process`: each guards with `typeof process` or the node-only entry. */
const ALLOWLIST = new Set([
	"runtime/env.ts",
	"observability/index.ts",
	"policy/cache.ts",
	"mcp/safe-fetch-node.ts",
]);

function walk(dir: string, out: string[] = []): string[] {
	for (const name of readdirSync(dir)) {
		const full = join(dir, name);
		if (statSync(full).isDirectory()) walk(full, out);
		else if (full.endsWith(".ts") && !full.endsWith(".d.ts")) out.push(full);
	}
	return out;
}

describe("no bare process access in src", () => {
	it("only allowlisted files read process", () => {
		const offenders: string[] = [];
		for (const file of walk(SRC)) {
			const rel = relative(SRC, file);
			if (ALLOWLIST.has(rel)) continue;
			readFileSync(file, "utf8")
				.split("\n")
				.forEach((line, i) => {
					const trimmed = line.trim();
					if (trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("/*"))
						return;
					// Messages that merely quote `process.env.X` inside a string literal are fine.
					const code = line.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');
					if (/(^|[^.\w])process\s*(\?\.|\.)|globalThis\.process/.test(code)) {
						offenders.push(`${rel}:${i + 1}: ${trimmed}`);
					}
				});
		}
		expect(offenders).toEqual([]);
	});
});
