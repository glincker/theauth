import { randomBytes } from "node:crypto";
import { readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { scaffold } from "../src/scaffold.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const PLACEHOLDERS = ["__APP_NAME__", "__DB_DRIVER__", "__DB_DRIVER_VERSION__", "__WORKSPACE__"];

async function fileExists(p: string): Promise<boolean> {
	return stat(p)
		.then((s) => s.isFile())
		.catch(() => false);
}

async function collectFiles(dir: string): Promise<string[]> {
	const result: string[] = [];
	const entries = await readdir(dir, { withFileTypes: true });
	for (const entry of entries) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			result.push(...(await collectFiles(full)));
		} else {
			result.push(full);
		}
	}
	return result;
}

function randomDir(): string {
	return join(tmpdir(), `theauth-test-${randomBytes(6).toString("hex")}`);
}

describe("scaffold – next-saas", () => {
	const dirs: string[] = [];

	afterEach(async () => {
		await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
		dirs.length = 0;
	});

	it("creates expected files", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);

		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "test-app",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});

		const expected = [
			"package.json",
			"src/lib/theauth.ts",
			"src/app/layout.tsx",
			".gitignore",
			"src/app/api/auth/[...theauth]/route.ts",
			"src/app/page.tsx",
			"src/app/agents/page.tsx",
			".env.example",
			"drizzle.config.ts",
			"next.config.mjs",
			"tsconfig.json",
		];

		for (const rel of expected) {
			const exists = await fileExists(join(targetDir, rel));
			expect(exists, `Expected file missing: ${rel}`).toBe(true);
		}
	});

	it("replaces __APP_NAME__ in package.json", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);

		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "my-cool-app",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});

		const pkg = await readFile(join(targetDir, "package.json"), "utf-8");
		expect(pkg).toContain('"name": "my-cool-app"');
	});

	it("replaces __APP_NAME__ in layout.tsx", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);

		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "layout-test",
			dbDriver: "pg",
			dbUrl: "",
		});

		const layout = await readFile(join(targetDir, "src/app/layout.tsx"), "utf-8");
		expect(layout).toContain("layout-test");
	});

	it("leaves no raw placeholders in any file", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);

		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "placeholder-check",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});

		const files = await collectFiles(targetDir);
		for (const file of files) {
			const content = await readFile(file, "utf-8");
			for (const placeholder of PLACEHOLDERS) {
				expect(
					content,
					`Placeholder ${placeholder} found in ${file.replace(targetDir, "")}`,
				).not.toContain(placeholder);
			}
		}
	});

	it("uses pg driver when selected", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);

		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "pg-app",
			dbDriver: "pg",
			dbUrl: "",
		});

		const pkg = await readFile(join(targetDir, "package.json"), "utf-8");
		expect(pkg).toContain('"pg"');

		const theauth = await readFile(join(targetDir, "src/lib/theauth.ts"), "utf-8");
		expect(theauth).toContain("pg");
	});

	it("renames _gitignore to .gitignore", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);

		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "gitignore-test",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});

		const hasGitignore = await fileExists(join(targetDir, ".gitignore"));
		const hasUnderscore = await fileExists(join(targetDir, "_gitignore"));
		expect(hasGitignore).toBe(true);
		expect(hasUnderscore).toBe(false);
	});
});

describe("scaffold – error handling", () => {
	it("throws for unknown template", async () => {
		const targetDir = randomDir();
		await expect(
			scaffold({
				targetDir,
				template: "does-not-exist",
				appName: "test",
				dbDriver: "sql.js",
				dbUrl: "",
			}),
		).rejects.toThrow('Template "does-not-exist" not found');
	});
});

describe("scaffold: dependency versions", () => {
	const dirs: string[] = [];

	afterEach(async () => {
		await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
		dirs.length = 0;
	});

	async function workspaceVersion(rel: string): Promise<string> {
		const raw = await readFile(join(__dirname, "..", "..", rel, "package.json"), "utf-8");
		return (JSON.parse(raw) as { version: string }).version;
	}

	it("pins @glinr packages in hono-mcp to the current workspace versions", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);
		await scaffold({
			targetDir,
			template: "hono-mcp",
			appName: "versions-app",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});
		const pkg = JSON.parse(await readFile(join(targetDir, "package.json"), "utf-8")) as {
			dependencies: Record<string, string>;
		};
		expect(pkg.dependencies["@glinr/theauth-hono"]).toBe(
			`^${await workspaceVersion("adapters/hono")}`,
		);
		expect(pkg.dependencies["@glinr/theauth"]).toBe(`^${await workspaceVersion("core")}`);
	});

	it("pins @glinr packages in next-saas to the current workspace versions", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);
		await scaffold({
			targetDir,
			template: "next-saas",
			appName: "versions-next",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});
		const pkg = JSON.parse(await readFile(join(targetDir, "package.json"), "utf-8")) as {
			dependencies: Record<string, string>;
		};
		expect(pkg.dependencies["@glinr/theauth-nextjs"]).toBe(
			`^${await workspaceVersion("adapters/nextjs")}`,
		);
		expect(pkg.dependencies["@glinr/theauth-react"]).toBe(`^${await workspaceVersion("react")}`);
	});

	it("lists the sqlite driver and zod the template needs", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);
		await scaffold({
			targetDir,
			template: "hono-mcp",
			appName: "driver-app",
			dbDriver: "sql.js",
			dbUrl: "./theauth.db",
		});
		const pkg = JSON.parse(await readFile(join(targetDir, "package.json"), "utf-8")) as {
			dependencies: Record<string, string>;
		};
		expect(pkg.dependencies["sql.js"]).toBeDefined();
		expect(pkg.dependencies.zod).toBeDefined();
		expect(pkg.dependencies["better-sqlite3"]).toBeUndefined();
	});

	it("leaves no workspace placeholders behind", async () => {
		const targetDir = randomDir();
		dirs.push(targetDir);
		await scaffold({
			targetDir,
			template: "hono-mcp",
			appName: "ph-app",
			dbDriver: "pg",
			dbUrl: "",
		});
		for (const file of await collectFiles(targetDir)) {
			expect(await readFile(file, "utf-8")).not.toContain("__WORKSPACE__");
		}
	});
});
