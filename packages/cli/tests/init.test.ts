import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InitSuccess } from "../src/init.js";
import {
	detectFramework,
	detectPackageManager,
	formatInit,
	parseInitArgs,
	runInit,
} from "../src/init.js";
import type { Framework } from "../src/init-templates.js";

const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`);

let dir: string;
beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "theauth-init-"));
});
afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

async function init(args: string[]): Promise<InitSuccess> {
	const result = await runInit(parseInitArgs(["--yes", `--dir=${dir}`, ...args], dir), {
		interactive: false,
	});
	if (!result.success) throw new Error(result.error.message);
	return result;
}

const MOUNT_FILES: Record<Framework, string> = {
	hono: "src/server.ts",
	express: "src/server.ts",
	fastify: "src/server.ts",
	nextjs: "app/api/theauth/[...theauth]/route.ts",
	sveltekit: "src/routes/api/theauth/[...path]/+server.ts",
	nuxt: "server/api/theauth/[...path].ts",
};

describe("parseInitArgs", () => {
	it("parses flags", () => {
		expect(
			parseInitArgs(["--framework", "fastify", "--db=postgres", "--mcp", "--yes", "--force"], "/x"),
		).toMatchObject({
			framework: "fastify",
			database: "postgres",
			mcp: true,
			yes: true,
			force: true,
		});
		expect(parseInitArgs(["--dir", "app"], "/x").dir).toBe("/x/app");
	});

	it("reports bad input", () => {
		expect(parseInitArgs(["--framework", "rails"], "/x").error).toMatch(/--framework/);
		expect(parseInitArgs(["--db", "oracle"], "/x").error).toMatch(/--db/);
		expect(parseInitArgs(["--bogus"], "/x").error).toMatch(/Unknown option/);
	});
});

describe("detection", () => {
	it("prefers the meta framework over the server library under it", () => {
		expect(detectFramework({ dependencies: { next: "15", express: "4" } })).toBe("nextjs");
		expect(detectFramework({ devDependencies: { "@sveltejs/kit": "2" } })).toBe("sveltekit");
		expect(detectFramework({ dependencies: { hono: "4" } })).toBe("hono");
		expect(detectFramework({ dependencies: {} })).toBeNull();
		expect(detectFramework(null)).toBeNull();
	});

	it("reads the package manager from packageManager, then lockfiles", async () => {
		expect(detectPackageManager(dir, { packageManager: "pnpm@9.1.0" })).toBe("pnpm");
		expect(detectPackageManager(dir, null)).toBe("npm");
		await writeFile(join(dir, "yarn.lock"), "");
		expect(detectPackageManager(dir, null)).toBe("yarn");
	});
});

describe("theauth init", () => {
	for (const framework of Object.keys(MOUNT_FILES) as Framework[]) {
		it(`writes the expected files for ${framework}`, async () => {
			const result = await init(["--framework", framework]);
			for (const file of [
				"src/theauth.ts",
				"src/seed.ts",
				MOUNT_FILES[framework],
				".env.example",
				".env",
				".gitignore",
			]) {
				expect(existsSync(join(dir, file)), file).toBe(true);
			}
			const mount = await readFile(join(dir, MOUNT_FILES[framework]), "utf8");
			expect(mount).toContain(`@glinr/theauth-${framework === "nextjs" ? "nextjs" : framework}`);
			const seed = await readFile(join(dir, "src/seed.ts"), "utf8");
			expect(seed.indexOf("user.create")).toBeGreaterThan(-1);
			expect(seed.indexOf("user.create")).toBeLessThan(seed.indexOf("agent.create"));
			expect(result.nextSteps).toContain("/api/theauth/agents");
			expect(result.nextSteps).toContain("curl");
		});
	}

	it("uses SQLite file storage by default, never :memory:", async () => {
		await init(["--framework", "hono"]);
		const instance = await readFile(join(dir, "src/theauth.ts"), "utf8");
		expect(instance).toContain('provider: "sqlite-native"');
		expect(instance).toContain("./theauth.db");
		expect(instance).not.toContain(":memory:");
	});

	it("honors --db postgres", async () => {
		const result = await init(["--framework", "hono", "--db", "postgres"]);
		expect(await readFile(join(dir, "src/theauth.ts"), "utf8")).toContain('provider: "postgres"');
		expect(result.nextSteps).toContain(" pg ");
	});

	it("generates a 32 byte secret in .env and gitignores it", async () => {
		await init(["--framework", "hono"]);
		const env = await readFile(join(dir, ".env"), "utf8");
		expect(env).toMatch(/^THEAUTH_SECRET=[0-9a-f]{64}$/m);
		expect(env).toMatch(/^ADMIN_API_KEY=[0-9a-f]{64}$/m);
		expect(await readFile(join(dir, ".gitignore"), "utf8")).toMatch(/^\.env$/m);
		expect(await readFile(join(dir, ".env.example"), "utf8")).toMatch(/^THEAUTH_SECRET=$/m);
	});

	it("appends to an existing .gitignore without rewriting it", async () => {
		await writeFile(join(dir, ".gitignore"), "dist");
		await init(["--framework", "hono"]);
		const text = await readFile(join(dir, ".gitignore"), "utf8");
		expect(text.startsWith("dist\n")).toBe(true);
		expect(text).toContain(".env");
	});

	it("is idempotent: a re-run skips every file and keeps the secrets", async () => {
		await init(["--framework", "hono"]);
		const before = await readFile(join(dir, ".env"), "utf8");
		await writeFile(join(dir, "src/server.ts"), "// mine\n");
		const second = await init(["--framework", "hono"]);
		expect(second.files.every((f) => f.status === "skipped")).toBe(true);
		expect(await readFile(join(dir, "src/server.ts"), "utf8")).toBe("// mine\n");
		expect(await readFile(join(dir, ".env"), "utf8")).toBe(before);
	});

	it("--force replaces generated files but never .env", async () => {
		await init(["--framework", "hono"]);
		const env = await readFile(join(dir, ".env"), "utf8");
		await writeFile(join(dir, "src/server.ts"), "// mine\n");
		const forced = await init(["--framework", "hono", "--force"]);
		expect(forced.files.find((f) => f.file === "src/server.ts")?.status).toBe("overwritten");
		expect(await readFile(join(dir, "src/server.ts"), "utf8")).toContain("theAuthHono");
		expect(await readFile(join(dir, ".env"), "utf8")).toBe(env);
	});

	it("detects the framework and package manager from the project", async () => {
		await writeFile(
			join(dir, "package.json"),
			JSON.stringify({
				type: "module",
				packageManager: "pnpm@9.0.0",
				dependencies: { express: "4" },
			}),
		);
		const result = await init([]);
		expect(result.framework).toBe("express");
		expect(result.packageManager).toBe("pnpm");
		expect(result.nextSteps).toContain("pnpm add @glinr/theauth");
		expect(result.notes.join(" ")).toContain("Detected express");
	});

	it("places the Next.js route under src/app when src exists", async () => {
		await mkdir(join(dir, "src"));
		await init(["--framework", "nextjs"]);
		expect(existsSync(join(dir, "src/app/api/theauth/[...theauth]/route.ts"))).toBe(true);
		const route = await readFile(join(dir, "src/app/api/theauth/[...theauth]/route.ts"), "utf8");
		expect(route).toContain('from "../../../../theauth"');
	});

	it("skips --mcp with a note instead of failing", async () => {
		const result = await init(["--framework", "hono", "--mcp"]);
		expect(result.notes.join(" ")).toContain("--mcp skipped");
	});

	it("warns when a server framework project is not ESM", async () => {
		await writeFile(join(dir, "package.json"), JSON.stringify({ dependencies: { hono: "4" } }));
		const result = await init([]);
		expect(result.notes.join(" ")).toContain('"type": "module"');
	});

	it("writes no dash characters anywhere in generated files or output", async () => {
		for (const framework of Object.keys(MOUNT_FILES) as Framework[]) {
			const target = await mkdtemp(join(tmpdir(), "theauth-init-dash-"));
			try {
				const result = await runInit(
					parseInitArgs(["--yes", `--dir=${target}`, "--framework", framework, "--mcp"], target),
					{ interactive: false },
				);
				if (!result.success) throw new Error(result.error.message);
				const texts = [formatInit(result)];
				for (const f of result.files) {
					if (f.file !== ".env") texts.push(await readFile(join(target, f.file), "utf8"));
				}
				for (const text of texts) {
					expect(text).not.toMatch(DASHES);
					expect(text).not.toMatch(/ -- /);
				}
			} finally {
				await rm(target, { recursive: true, force: true });
			}
		}
	});
});
