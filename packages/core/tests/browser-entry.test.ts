import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
const NODE_ONLY = [
	"nodemailer",
	"pg",
	"mysql2",
	"mysql2/promise",
	"better-sqlite3",
	"@libsql/client",
	"zlib",
	"node:zlib",
	"node:fs",
	"fs",
	"drizzle-orm/better-sqlite3",
	"drizzle-orm/node-postgres",
	"drizzle-orm/mysql2",
	"drizzle-orm/libsql",
	"./db/database.js",
];
const SPEC = /(?:from\s*|import\s*\(\s*|import\s+|require\(\s*)["']([^"']+)["']/g;

function resolveLocal(from: string, spec: string): string {
	return join(dirname(from), spec.replace(/\.js$/, ".ts")).replace(/\/index\.ts$/, "/index.ts");
}

/** Walk every static and dynamic specifier reachable from the browser entry. */
function reachable(entry: string): { files: Set<string>; specs: Map<string, string[]> } {
	const files = new Set<string>();
	const specs = new Map<string, string[]>();
	const queue = [entry];
	while (queue.length > 0) {
		const file = queue.pop() as string;
		if (files.has(file)) continue;
		files.add(file);
		const text = readFileSync(file, "utf8")
			.replace(/\/\*[\s\S]*?\*\//g, "")
			.replace(/^\s*\/\/.*$/gm, "");
		for (const match of text.matchAll(SPEC)) {
			const spec = match[1] as string;
			const isTypeOnly = new RegExp(`import\\s+type[^;]*["']${spec}["']`).test(text);
			if (spec.startsWith(".")) {
				if (!isTypeOnly) queue.push(resolveLocal(file, spec));
			} else {
				const list = specs.get(spec) ?? [];
				list.push(file);
				specs.set(spec, list);
			}
		}
	}
	return { files, specs };
}

describe("browser entry", () => {
	const { files, specs } = reachable(join(SRC, "browser.ts"));

	it("imports no node-only module name", () => {
		for (const name of NODE_ONLY.filter((n) => !n.startsWith("."))) {
			expect(specs.has(name), `${name} reachable from browser.ts`).toBe(false);
		}
		expect([...specs.keys()].filter((s) => s.startsWith("node:"))).toEqual([]);
	});

	it("never reaches the node database factory", () => {
		const hit = [...files].filter((f) => f.endsWith("/db/database.ts"));
		expect(hit).toEqual([]);
	});

	it("rejects node providers and demands a sqlJs loader", async () => {
		const { createTheAuth } = await import("../src/browser.js");
		await expect(
			createTheAuth({ database: { provider: "postgres", url: "postgres://x" } }),
		).rejects.toThrow(/not available in the browser entry/);
		await expect(
			createTheAuth({ database: { provider: "sqlite", url: ":memory:" } }),
		).rejects.toThrow(/sqlJs loader/);
	});

	it("runs on a caller-supplied sql.js", async () => {
		const { createTheAuth } = await import("../src/browser.js");
		const initSqlJs = (await import("sql.js")).default;
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			sqlJs: () => initSqlJs(),
		});
		expect(typeof auth.policy.evaluate).toBe("function");
	});
});
