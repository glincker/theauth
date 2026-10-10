import { randomBytes } from "node:crypto";
import { readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseArgs } from "../src/args.js";
import { scaffold } from "../src/scaffold.js";

type Handler = (c: FakeContext) => Promise<unknown>;

interface FakeContext {
	req: { method: string; header: (name: string) => string | undefined };
	json: (body: unknown, status?: number) => { body: unknown; status: number };
}

// Stand-ins for hono and @hono/node-server: they record the routes the
// generated server registers so the test can call the handlers directly.
const routes = vi.hoisted(() => new Map<string, unknown>());
const served = vi.hoisted(() => ({ port: 0, hostname: "" }));

vi.mock("hono", () => ({
	Hono: class {
		on(methods: string[], path: string, handler: unknown) {
			for (const m of methods) routes.set(`${m} ${path}`, handler);
		}
		get(path: string, handler: unknown) {
			routes.set(`GET ${path}`, handler);
		}
	},
}));

vi.mock("@hono/node-server", () => ({
	serve: (opts: { port: number; hostname: string }, onListen?: () => void) => {
		served.port = opts.port;
		served.hostname = opts.hostname;
		onListen?.();
	},
}));

function randomDir(): string {
	return join(tmpdir(), `theauth-first-run-${randomBytes(6).toString("hex")}`);
}

function call(key: string, method: string, token: string | null) {
	const handler = routes.get(key) as Handler;
	return handler({
		req: {
			method,
			header: (name) =>
				name === "authorization" && token !== null ? `Bearer ${token}` : undefined,
		},
		json: (body, status = 200) => ({ body, status }),
	}) as Promise<{ body: unknown; status: number }>;
}

describe("first-run template", () => {
	const dirs: string[] = [];
	afterEach(async () => {
		vi.unstubAllEnvs();
		await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
		dirs.length = 0;
	});

	async function generate(): Promise<string> {
		const targetDir = randomDir();
		dirs.push(targetDir);
		await scaffold({
			targetDir,
			template: "first-run",
			appName: "agent-demo",
			dbDriver: "sql.js",
			dbUrl: "",
		});
		return targetDir;
	}

	it("writes the expected files and no .env", async () => {
		const dir = await generate();
		for (const rel of [
			"package.json",
			"tsconfig.json",
			"README.md",
			".gitignore",
			".env.example",
			"src/server.ts",
		]) {
			expect((await stat(join(dir, rel))).isFile(), rel).toBe(true);
		}
		await expect(stat(join(dir, ".env"))).rejects.toThrow();
	});

	it("depends on core, hono and the node server only", async () => {
		const dir = await generate();
		const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf-8")) as {
			name: string;
			dependencies: Record<string, string>;
			scripts: Record<string, string>;
		};
		expect(pkg.name).toBe("agent-demo");
		expect(Object.keys(pkg.dependencies).sort()).toEqual([
			"@glinr/theauth",
			"@hono/node-server",
			"hono",
		]);
		expect(pkg.dependencies["@glinr/theauth"]).toMatch(/^\^\d+\.\d+\.\d+/);
		expect(pkg.scripts.start).toBe("tsx src/server.ts");
	});

	it("declares the github read permission and uses in memory sqlite", async () => {
		const dir = await generate();
		const server = await readFile(join(dir, "src/server.ts"), "utf-8");
		expect(server).toContain('permissions: [{ resource: "mcp:github:*", actions: ["read"] }]');
		expect(server).toContain('url: ":memory:"');
		expect(server).toContain("authorizeByToken");
		expect(server).not.toContain("__APP_NAME__");
	});

	it("allows the read, denies the delete, and audits both", { timeout: 30_000 }, async () => {
		const dir = await generate();
		const logs: string[] = [];
		vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
			logs.push(a.join(" "));
		});
		vi.stubEnv("PORT", "3456");
		await import(/* @vite-ignore */ join(dir, "src/server.ts"));

		expect(served).toEqual({ port: 3456, hostname: "127.0.0.1" });
		const token = logs.join("\n").match(/kv_[\w-]+/)?.[0] ?? "";
		expect(token).not.toBe("");

		const allowed = await call("GET /mcp/github/repos", "GET", token);
		expect(allowed.status).toBe(200);
		expect(allowed.body).toMatchObject({ action: "read", allowed: true });

		const denied = await call("DELETE /mcp/github/repos", "DELETE", token);
		expect(denied.status).toBe(403);
		expect(denied.body).toMatchObject({ action: "delete", allowed: false });

		const noToken = await call("GET /mcp/github/repos", "GET", null);
		expect(noToken.status).toBe(403);

		const audit = await call("GET /audit", "GET", null);
		const rows = audit.body as { action: string; result: string }[];
		expect(rows.map((r) => `${r.action}:${r.result}`).sort()).toEqual([
			"delete:denied",
			"read:allowed",
		]);

		// The printed commands are the ones a new user will paste.
		const printed = logs.join("\n");
		expect(printed).toContain("curl http://localhost:3456/mcp/github/repos");
		expect(printed).toContain("curl -X DELETE http://localhost:3456/mcp/github/repos");
		expect(printed).toContain("curl http://localhost:3456/audit");
		expect(printed).toContain("npx @glinr/theauth-cli dashboard");
	});
});

describe("parseArgs", () => {
	it("defaults to prompts and install", () => {
		expect(parseArgs([])).toMatchObject({ dir: null, template: null, yes: false, install: true });
	});

	it("reads a directory, --yes and --no-install", () => {
		expect(parseArgs(["my-app", "--yes", "--no-install"])).toMatchObject({
			dir: "my-app",
			yes: true,
			install: false,
			error: null,
		});
	});

	it("reads --template in both spellings and rejects unknown ones", () => {
		expect(parseArgs(["--template", "hono-mcp"]).template).toBe("hono-mcp");
		expect(parseArgs(["--template=first-run"]).template).toBe("first-run");
		expect(parseArgs(["--template", "nope"]).error).toContain('Unknown template "nope"');
	});

	it("rejects unknown options and extra arguments", () => {
		expect(parseArgs(["--wat"]).error).toContain("Unknown option");
		expect(parseArgs(["a", "b"]).error).toContain("Unexpected argument");
	});
});
