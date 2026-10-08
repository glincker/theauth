import { existsSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assetCandidates } from "./docs-search.js";

export type AgentTarget = "claude" | "cursor" | "vscode";
export const ALL_TARGETS: readonly AgentTarget[] = ["claude", "cursor", "vscode"];

export interface InitAgentOptions {
	cwd: string;
	targets: readonly AgentTarget[];
	force: boolean;
	dryRun: boolean;
}

export interface InitAgentAction {
	file: string;
	status: "created" | "updated" | "unchanged" | "skipped";
	note?: string;
}

const here = dirname(fileURLToPath(import.meta.url));
export const MCP_COMMAND = "npx";
export const MCP_ARGS = ["-y", "@glinr/theauth-cli", "mcp"];

export function readSkill(): string | null {
	const candidates = [
		...assetCandidates("SKILL.md"),
		join(here, "../../../../skills/theauth/SKILL.md"),
		join(here, "../../../skills/theauth/SKILL.md"),
	];
	for (const file of candidates) {
		if (existsSync(file)) return readFileSync(file, "utf8");
	}
	return null;
}

/** Split `---` frontmatter from the body. */
export function splitFrontmatter(source: string): { description: string; body: string } {
	const m = /^---\n([\s\S]*?)\n---\n?/.exec(source);
	if (!m?.[1]) return { description: "", body: source };
	const d = /^description:\s*(.*)$/m.exec(m[1]);
	return {
		description: (d?.[1] ?? "").replace(/^["']|["']$/g, ""),
		body: source.slice(m[0].length),
	};
}

function cursorRule(skill: string): string {
	const { description, body } = splitFrontmatter(skill);
	return `---\ndescription: ${description}\nalwaysApply: false\n---\n${body}`;
}

async function writeIfChanged(
	file: string,
	content: string,
	opts: InitAgentOptions,
): Promise<InitAgentAction> {
	const rel = file.startsWith(opts.cwd) ? file.slice(opts.cwd.length + 1) : file;
	const exists = existsSync(file);
	if (exists) {
		const current = await readFile(file, "utf8");
		if (current === content) return { file: rel, status: "unchanged" };
		if (!opts.force) {
			return {
				file: rel,
				status: "skipped",
				note: "exists and differs, pass --force to overwrite",
			};
		}
	}
	if (!opts.dryRun) {
		await mkdir(dirname(file), { recursive: true });
		await writeFile(file, content, "utf8");
	}
	return { file: rel, status: exists ? "updated" : "created" };
}

/** Add the theauth server to a JSON MCP config without touching other servers. */
async function mergeMcpConfig(
	file: string,
	key: "mcpServers" | "servers",
	entry: Record<string, unknown>,
	opts: InitAgentOptions,
): Promise<InitAgentAction> {
	const rel = file.startsWith(opts.cwd) ? file.slice(opts.cwd.length + 1) : file;
	let doc: Record<string, unknown> = {};
	const exists = existsSync(file);
	if (exists) {
		try {
			const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
			if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
				throw new Error("not an object");
			doc = parsed as Record<string, unknown>;
		} catch {
			return {
				file: rel,
				status: "skipped",
				note: "not valid JSON (comments?), add the server by hand",
			};
		}
	}
	const servers = (typeof doc[key] === "object" && doc[key] !== null ? doc[key] : {}) as Record<
		string,
		unknown
	>;
	if (servers.theauth !== undefined && !opts.force) {
		return { file: rel, status: "unchanged", note: "theauth server already configured" };
	}
	const next = { ...doc, [key]: { ...servers, theauth: entry } };
	if (!opts.dryRun) {
		await mkdir(dirname(file), { recursive: true });
		await writeFile(file, `${JSON.stringify(next, null, 2)}\n`, "utf8");
	}
	return { file: rel, status: exists ? "updated" : "created" };
}

export async function runInitAgent(opts: InitAgentOptions): Promise<InitAgentAction[]> {
	const skill = readSkill();
	if (!skill)
		throw new Error("Skill file not found in this install. Reinstall @glinr/theauth-cli.");
	const actions: InitAgentAction[] = [];
	const stdioEntry = { command: MCP_COMMAND, args: MCP_ARGS };
	for (const target of opts.targets) {
		if (target === "claude") {
			actions.push(
				await writeIfChanged(join(opts.cwd, ".claude/skills/theauth/SKILL.md"), skill, opts),
			);
			actions.push(
				await mergeMcpConfig(join(opts.cwd, ".mcp.json"), "mcpServers", stdioEntry, opts),
			);
		} else if (target === "cursor") {
			actions.push(
				await writeIfChanged(join(opts.cwd, ".cursor/rules/theauth.mdc"), cursorRule(skill), opts),
			);
			actions.push(
				await mergeMcpConfig(join(opts.cwd, ".cursor/mcp.json"), "mcpServers", stdioEntry, opts),
			);
		} else {
			actions.push(
				await mergeMcpConfig(
					join(opts.cwd, ".vscode/mcp.json"),
					"servers",
					{ type: "stdio", ...stdioEntry },
					opts,
				),
			);
		}
	}
	return actions;
}

export interface InitAgentArgs {
	options: InitAgentOptions | null;
	error: string | null;
}

export const INIT_AGENT_HELP = `
theauth init --agent - install the theAuth skill and MCP server config for coding assistants

Usage:
  theauth init --agent [--target claude,cursor,vscode] [--force] [--dry-run]

Writes:
  claude   .claude/skills/theauth/SKILL.md and .mcp.json
  cursor   .cursor/rules/theauth.mdc and .cursor/mcp.json
  vscode   .vscode/mcp.json

Existing files are not overwritten and other MCP servers are kept. Use --force to replace the theauth entries.
`;

export function parseInitAgentArgs(args: string[], cwd: string): InitAgentArgs {
	let targets: AgentTarget[] = [...ALL_TARGETS];
	let force = false;
	let dryRun = false;
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		if (a === "--agent") continue;
		if (a === "--force") force = true;
		else if (a === "--dry-run") dryRun = true;
		else if (a === "--target" || a.startsWith("--target=")) {
			const value = a.includes("=") ? a.split("=")[1] : args[++i];
			const parts = (value ?? "").split(",").filter((p) => p !== "");
			const bad = parts.find((p) => !(ALL_TARGETS as readonly string[]).includes(p));
			if (parts.length === 0 || bad !== undefined) {
				return {
					options: null,
					error: `Unknown target "${bad ?? ""}". Use claude, cursor, vscode.`,
				};
			}
			targets = parts as AgentTarget[];
		} else {
			return { options: null, error: `Unknown option: ${a}` };
		}
	}
	return { options: { cwd, targets, force, dryRun }, error: null };
}
