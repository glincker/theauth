import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, symlinkSync } from "node:fs";
import { readdir, readFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { fillSecrets, scaffold } from "../src/scaffold.js";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(here, "..");
const repoPackages = join(pkgRoot, "..");
const TEMPLATES = ["hono-mcp", "next-saas", "cloudflare-workers"] as const;
const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]|&mdash;|&ndash;`);
const dirs: string[] = [];

function tempDir(): string {
	// Inside the package so module resolution can climb to the workspace node_modules.
	const dir = join(pkgRoot, `.tmp-template-${randomBytes(5).toString("hex")}`);
	dirs.push(dir);
	return dir;
}

afterEach(async () => {
	await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
	dirs.length = 0;
});

async function allFiles(dir: string): Promise<string[]> {
	const out: string[] = [];
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...(await allFiles(full)));
		else out.push(full);
	}
	return out;
}

describe("templates on real storage", () => {
	for (const template of TEMPLATES) {
		it(`${template}: no dashes, no memory database, no dev secret fallbacks, doctor script`, async () => {
			const target = tempDir();
			await scaffold({
				targetDir: target,
				template,
				appName: "demo",
				dbDriver: "better-sqlite3",
				dbUrl: "./theauth.db",
			});
			for (const file of await allFiles(target)) {
				const text = await readFile(file, "utf-8");
				const rel = file.replace(target, "");
				expect(text, `dash in ${rel}`).not.toMatch(DASHES);
				expect(text, `:memory: in ${rel}`).not.toContain(":memory:");
				expect(text, `dev secret in ${rel}`).not.toMatch(/dev-secret|dev-mcp-signing|change-me/);
				expect(text, `placeholder in ${rel}`).not.toMatch(/__(APP_NAME|DB_[A-Z_]+|WORKSPACE)__/);
			}
			const pkg = JSON.parse(await readFile(join(target, "package.json"), "utf-8")) as {
				scripts: Record<string, string>;
			};
			expect(pkg.scripts.doctor).toContain("doctor");
		});
	}

	it("writes .env with generated secrets and keeps an existing one", async () => {
		const target = tempDir();
		await scaffold({
			targetDir: target,
			template: "hono-mcp",
			appName: "demo",
			dbDriver: "better-sqlite3",
			dbUrl: "./theauth.db",
		});
		const env = await readFile(join(target, ".env"), "utf-8");
		for (const name of ["THEAUTH_SECRET", "ADMIN_API_KEY", "MCP_SIGNING_SECRET"]) {
			expect(env).toMatch(new RegExp(`^${name}=[0-9a-f]{64}$`, "m"));
		}
		expect(env).toContain("DATABASE_URL=./theauth.db");
		expect(await readFile(join(target, ".gitignore"), "utf-8")).toContain(".env");
	});

	it("fillSecrets only fills empty secret lines", () => {
		const out = fillSecrets("THEAUTH_SECRET=\nADMIN_API_KEY=keep-me\nPORT=1\n");
		expect(out).toMatch(/^THEAUTH_SECRET=[0-9a-f]{64}$/m);
		expect(out).toContain("ADMIN_API_KEY=keep-me");
	});

	it("hono-mcp seeds the owner with user.create and mounts the adapter wrapper", async () => {
		const target = tempDir();
		await scaffold({
			targetDir: target,
			template: "hono-mcp",
			appName: "demo",
			dbDriver: "better-sqlite3",
			dbUrl: "./theauth.db",
		});
		const server = await readFile(join(target, "src/server.ts"), "utf-8");
		expect(server).toContain("theauth.user.create");
		expect(server).toContain("theAuthHono(");
		expect(server).not.toContain("insert(users)");
		const instance = await readFile(join(target, "src/lib/theauth.ts"), "utf-8");
		expect(instance).toContain("sqlite-native");
	});

	it("hono-mcp typechecks against the workspace packages", async () => {
		const honoDir = join(repoPackages, "adapters", "hono");
		const nodeServer = join(pkgRoot, "..", "..", "node_modules", ".pnpm");
		const nodeServerDir = existsSync(nodeServer)
			? (await readdir(nodeServer)).find((n) => n.startsWith("@hono+node-server@"))
			: undefined;
		const coreDist = join(repoPackages, "core", "dist", "http", "index.d.ts");
		const honoDist = join(honoDir, "dist", "index.d.ts");
		const tsc = join(pkgRoot, "node_modules", ".bin", "tsc");
		if (!nodeServerDir || !existsSync(coreDist) || !existsSync(honoDist) || !existsSync(tsc)) {
			console.warn("typecheck skipped: workspace packages are not built");
			return;
		}
		const target = tempDir();
		await scaffold({
			targetDir: target,
			template: "hono-mcp",
			appName: "demo",
			dbDriver: "better-sqlite3",
			dbUrl: "./theauth.db",
		});
		const modules = join(target, "node_modules");
		mkdirSync(join(modules, "@glinr"), { recursive: true });
		mkdirSync(join(modules, "@hono"), { recursive: true });
		symlinkSync(join(repoPackages, "core"), join(modules, "@glinr", "theauth"));
		symlinkSync(honoDir, join(modules, "@glinr", "theauth-hono"));
		symlinkSync(join(honoDir, "node_modules", "hono"), join(modules, "hono"));
		symlinkSync(
			join(nodeServer, nodeServerDir, "node_modules", "@hono", "node-server"),
			join(modules, "@hono", "node-server"),
		);
		symlinkSync(join(pkgRoot, "node_modules", "@types"), join(modules, "@types"));
		expect(() =>
			execFileSync(tsc, ["--noEmit", "-p", join(target, "tsconfig.json")], { stdio: "pipe" }),
		).not.toThrow();
	}, 120_000);
});
