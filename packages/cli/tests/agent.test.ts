import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DocPage } from "../src/agent/docs-search.js";
import { searchDocs, setDocPages } from "../src/agent/docs-search.js";
import { readSkill, runInitAgent, splitFrontmatter } from "../src/agent/init-agent.js";
import { analyzeConfigSource, inspectProject } from "../src/agent/inspect.js";
import { handleMessage, serveStdio } from "../src/agent/mcp-server.js";
import { PLUGIN_CATALOG, scaffoldPlugin } from "../src/agent/plugin-catalog.js";
import { generateSchema } from "../src/agent/schema.js";
import { callTool } from "../src/agent/tools.js";

const pages: DocPage[] = [
	{
		slug: "quickstart",
		title: "Quickstart",
		description: "Get going",
		url: "u/q",
		body: "Create an agent and authorize it.",
	},
	{
		slug: "mcp",
		title: "MCP OAuth 2.1",
		description: "Authorization server",
		url: "u/m",
		body: "PKCE S256 and resource indicators.",
	},
];

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "theauth-agent-"));
	setDocPages(pages);
});
afterEach(() => setDocPages(null));

describe("docs search", () => {
	it("ranks title matches first and returns a snippet", () => {
		const hits = searchDocs(pages, "mcp pkce");
		expect(hits[0]?.slug).toBe("mcp");
		expect(hits[0]?.snippet).toContain("PKCE");
	});
	it("returns nothing for empty or unmatched queries", () => {
		expect(searchDocs(pages, "  ")).toEqual([]);
		expect(searchDocs(pages, "zzzzzz")).toEqual([]);
	});
});

describe("plugin catalog", () => {
	it("scaffolds a known plugin with session note when needed", () => {
		const r = scaffoldPlugin("magic-link");
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.text).toContain('import { magicLink } from "@glinr/theauth";');
			expect(r.text).toContain("auth: { session");
		}
	});
	it("includes an install line for packages outside core", () => {
		const r = scaffoldPlugin("email-password", "npm");
		expect(r.ok && r.text).toContain("npm install @glinr/theauth-email");
	});
	it("rejects unknown plugins and lists the known ones", () => {
		const r = scaffoldPlugin("nope");
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.message).toContain("magic-link");
	});
	it("only references factories the core package really exports", async () => {
		const core = (await import("@glinr/theauth")) as Record<string, unknown>;
		for (const p of PLUGIN_CATALOG.filter((c) => c.importFrom === "@glinr/theauth")) {
			expect(typeof core[p.factory], p.factory).toBe("function");
		}
	}, 30_000);
});

describe("inspect", () => {
	it("reports config shape and env var names but never secret values", () => {
		const secret = "super-secret-value-123456789012345678901234";
		writeFileSync(join(dir, ".env"), `THEAUTH_SESSION_SECRET=${secret}\nOTHER=1\n`);
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: { "@glinr/theauth": "^4.0.0", react: "1" } }),
		);
		mkdirSync(join(dir, "src"));
		writeFileSync(
			join(dir, "src/auth.ts"),
			`const t = await createTheAuth({ database: { provider: "postgres", url: "postgres://u:${secret}@h/db" }, agents: { enabled: true }, plugins: [passkey({ rpName: "a" }), twoFactor()] });`,
		);
		const report = inspectProject(dir);
		const json = JSON.stringify(report);
		expect(json).not.toContain(secret);
		expect(report.packages).toEqual({ "@glinr/theauth": "^4.0.0" });
		expect(report.envVarNames).toEqual(["THEAUTH_SESSION_SECRET"]);
		expect(report.configFiles[0]).toMatchObject({
			file: join("src", "auth.ts"),
			databaseProvider: "postgres",
			agentsConfigured: true,
			plugins: ["passkey", "two-factor"],
		});
	});
	it("ignores files without createTheAuth", () => {
		expect(analyzeConfigSource("a.ts", "export const x = 1")).toBeNull();
	});
});

describe("mcp protocol", () => {
	const ctx = { cwd: process.cwd() };
	it("answers initialize and echoes a supported protocol version", async () => {
		const r = await handleMessage(
			{ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } },
			ctx,
			"9.9.9",
		);
		expect(r).toMatchObject({
			id: 1,
			result: { protocolVersion: "2024-11-05", serverInfo: { name: "theauth", version: "9.9.9" } },
		});
	});
	it("lists the five tools, all read-only", async () => {
		const r = await handleMessage({ jsonrpc: "2.0", id: 2, method: "tools/list" }, ctx, "1");
		const tools = (
			r as { result: { tools: { name: string; annotations: { readOnlyHint: boolean } }[] } }
		).result.tools;
		expect(tools.map((t) => t.name).sort()).toEqual([
			"add_plugin",
			"generate_schema",
			"get_doc",
			"inspect",
			"search_docs",
		]);
		expect(tools.every((t) => t.annotations.readOnlyHint)).toBe(true);
	});
	it("returns no response for notifications and errors for unknown methods", async () => {
		expect(
			await handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }, ctx, "1"),
		).toBeNull();
		expect(await handleMessage({ jsonrpc: "2.0", id: 3, method: "nope" }, ctx, "1")).toMatchObject({
			error: { code: -32601 },
		});
	});
	it("calls tools and flags tool errors", async () => {
		const ok = await callTool("search_docs", { query: "agent" }, ctx);
		expect(ok.isError).toBe(false);
		expect(ok.text).toContain("Quickstart");
		expect((await callTool("add_plugin", { plugin: "x" }, ctx)).isError).toBe(true);
		expect((await callTool("get_doc", { slug: "missing" }, ctx)).isError).toBe(true);
		expect((await callTool("get_doc", { slug: "mcp" }, ctx)).text).toContain("PKCE");
	});
	it("serves newline-delimited JSON over streams and survives bad input", async () => {
		const input = new PassThrough();
		const output = new PassThrough();
		const chunks: string[] = [];
		output.on("data", (c: Buffer) => chunks.push(c.toString()));
		const done = serveStdio(input, output, ctx, "1");
		input.write("not json\n");
		input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" })}\n`);
		input.end();
		await done;
		const lines = chunks
			.join("")
			.trim()
			.split("\n")
			.map((l) => JSON.parse(l) as { id: unknown; error?: { code: number } });
		expect(lines.find((l) => l.error)?.error?.code).toBe(-32700);
		expect(lines.find((l) => l.id === 7)).toBeDefined();
	});
});

describe("generate_schema", () => {
	it("returns SQLite DDL for the requested features", async () => {
		const r = await generateSchema({ plugins: ["magic-link"], agents: true, mcp: false });
		if (!r.ok && /better-sqlite3|bindings|native/i.test(r.message)) return; // native module unavailable
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.text).toContain("CREATE TABLE theauth_agents");
			expect(r.text).toContain("theauth_magic_links");
		}
	}, 30_000);
	it("rejects unknown plugins", async () => {
		expect((await generateSchema({ plugins: ["zzz"], agents: true, mcp: false })).ok).toBe(false);
	});
});

describe("init --agent", () => {
	const base = () => ({
		cwd: dir,
		targets: ["claude", "cursor", "vscode"] as const,
		force: false,
		dryRun: false,
	});

	it("ships a skill with valid frontmatter", () => {
		const skill = readSkill();
		expect(skill).not.toBeNull();
		const fm = splitFrontmatter(skill ?? "");
		expect(skill).toMatch(/^---\nname: theauth\n/);
		expect(fm.description.length).toBeGreaterThan(40);
	});

	it("writes skill and MCP configs for all three assistants", async () => {
		const actions = await runInitAgent(base());
		expect(actions.every((a) => a.status === "created")).toBe(true);
		expect(existsSync(join(dir, ".claude/skills/theauth/SKILL.md"))).toBe(true);
		expect(readFileSync(join(dir, ".cursor/rules/theauth.mdc"), "utf8")).toMatch(
			/^---\ndescription: .+\nalwaysApply: false\n---\n/,
		);
		const claude = JSON.parse(readFileSync(join(dir, ".mcp.json"), "utf8"));
		expect(claude.mcpServers.theauth).toEqual({
			command: "npx",
			args: ["-y", "@glinr/theauth-cli", "mcp"],
		});
		const vscode = JSON.parse(readFileSync(join(dir, ".vscode/mcp.json"), "utf8"));
		expect(vscode.servers.theauth.type).toBe("stdio");
	});

	it("keeps other servers, is idempotent, and supports dry runs", async () => {
		writeFileSync(
			join(dir, ".mcp.json"),
			JSON.stringify({ mcpServers: { other: { command: "x" } } }),
		);
		await runInitAgent({ ...base(), targets: ["claude"] });
		const merged = JSON.parse(readFileSync(join(dir, ".mcp.json"), "utf8"));
		expect(Object.keys(merged.mcpServers).sort()).toEqual(["other", "theauth"]);
		const again = await runInitAgent({ ...base(), targets: ["claude"] });
		expect(again.every((a) => a.status === "unchanged")).toBe(true);

		const fresh = mkdtempSync(join(tmpdir(), "theauth-dry-"));
		await runInitAgent({ ...base(), cwd: fresh, dryRun: true });
		expect(existsSync(join(fresh, ".mcp.json"))).toBe(false);
	});

	it("skips unparseable JSON and protects edited files unless forced", async () => {
		mkdirSync(join(dir, ".vscode"));
		writeFileSync(join(dir, ".vscode/mcp.json"), "{ // comment\n}");
		const [vs] = await runInitAgent({ ...base(), targets: ["vscode"] });
		expect(vs?.status).toBe("skipped");
		expect(readFileSync(join(dir, ".vscode/mcp.json"), "utf8")).toContain("// comment");

		await runInitAgent({ ...base(), targets: ["claude"] });
		const skillPath = join(dir, ".claude/skills/theauth/SKILL.md");
		writeFileSync(skillPath, "edited");
		const [kept] = await runInitAgent({ ...base(), targets: ["claude"] });
		expect(kept?.status).toBe("skipped");
		expect(readFileSync(skillPath, "utf8")).toBe("edited");
		const [forced] = await runInitAgent({ ...base(), targets: ["claude"], force: true });
		expect(forced?.status).toBe("updated");
	});
});
