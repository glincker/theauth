import { loadDocPages, searchDocs } from "./docs-search.js";
import { inspectProject } from "./inspect.js";
import { PLUGIN_CATALOG, scaffoldPlugin } from "./plugin-catalog.js";
import { generateSchema } from "./schema.js";

export interface ToolResult {
	text: string;
	isError: boolean;
}

export interface ToolDefinition {
	name: string;
	description: string;
	inputSchema: Record<string, unknown>;
	annotations: { readOnlyHint: boolean; openWorldHint: boolean };
}

export interface ToolContext {
	cwd: string;
}

type Args = Record<string, unknown>;

const ok = (text: string): ToolResult => ({ text, isError: false });
const fail = (text: string): ToolResult => ({ text, isError: true });
const READ_ONLY = { readOnlyHint: true, openWorldHint: false } as const;
const PLUGIN_IDS = PLUGIN_CATALOG.map((p) => p.id);
const MAX_DOC_CHARS = 20_000;

export const TOOLS: readonly ToolDefinition[] = [
	{
		name: "search_docs",
		description: "Search the theAuth documentation. Returns matching pages with a snippet and URL.",
		inputSchema: {
			type: "object",
			properties: {
				query: { type: "string", description: "Words to search for" },
				limit: { type: "number", description: "Max results, 1 to 20 (default 5)" },
			},
			required: ["query"],
		},
		annotations: READ_ONLY,
	},
	{
		name: "get_doc",
		description: "Return the full text of one documentation page by slug, for example quickstart.",
		inputSchema: {
			type: "object",
			properties: { slug: { type: "string" } },
			required: ["slug"],
		},
		annotations: READ_ONLY,
	},
	{
		name: "add_plugin",
		description:
			"Return the install command, import and plugins-array entry for a theAuth plugin. Does not modify files; apply the edit yourself.",
		inputSchema: {
			type: "object",
			properties: {
				plugin: { type: "string", enum: PLUGIN_IDS },
				packageManager: { type: "string", enum: ["pnpm", "npm", "yarn", "bun"] },
			},
			required: ["plugin"],
		},
		annotations: READ_ONLY,
	},
	{
		name: "generate_schema",
		description:
			"Return the SQL tables theAuth creates for a feature set (SQLite DDL, built in memory). Tables are created automatically at startup; this is for review.",
		inputSchema: {
			type: "object",
			properties: {
				plugins: { type: "array", items: { type: "string", enum: PLUGIN_IDS } },
				agents: { type: "boolean", description: "Include agent identity tables (default true)" },
				mcp: { type: "boolean", description: "Include MCP tables (default false)" },
			},
		},
		annotations: READ_ONLY,
	},
	{
		name: "inspect",
		description:
			"Read-only summary of the local theAuth setup: installed @glinr/theauth* packages, detected config (database provider, plugins, agents, MCP) and env var names. Never returns secret values.",
		inputSchema: { type: "object", properties: {} },
		annotations: READ_ONLY,
	},
];

function str(args: Args, key: string): string | null {
	const v = args[key];
	return typeof v === "string" && v.trim() !== "" ? v.trim() : null;
}

export async function callTool(name: string, args: Args, ctx: ToolContext): Promise<ToolResult> {
	try {
		switch (name) {
			case "search_docs": {
				const query = str(args, "query");
				if (!query) return fail("query is required.");
				const pages = loadDocPages();
				if (pages.length === 0) {
					return fail(
						"Docs index not found. Reinstall @glinr/theauth-cli or read https://docs.theauth.dev/llms.txt.",
					);
				}
				const limit = typeof args.limit === "number" ? args.limit : 5;
				const hits = searchDocs(pages, query, limit);
				if (hits.length === 0) return ok(`No pages match "${query}".`);
				return ok(hits.map((h) => `${h.title} (${h.slug})\n${h.url}\n${h.snippet}`).join("\n\n"));
			}
			case "get_doc": {
				const slug = str(args, "slug");
				if (!slug) return fail("slug is required.");
				const page = loadDocPages().find((p) => p.slug === slug.replace(/^\/|\.mdx$/g, ""));
				if (!page) return fail(`No page "${slug}". Use search_docs to find slugs.`);
				const body =
					page.body.length > MAX_DOC_CHARS
						? `${page.body.slice(0, MAX_DOC_CHARS)}\n\n[truncated, full page at ${page.url}]`
						: page.body;
				return ok(`# ${page.title}\n${page.url}\n\n${body}`);
			}
			case "add_plugin": {
				const plugin = str(args, "plugin");
				if (!plugin) return fail("plugin is required.");
				const pm = str(args, "packageManager") ?? "pnpm";
				if (!["pnpm", "npm", "yarn", "bun"].includes(pm))
					return fail(`Unsupported packageManager "${pm}".`);
				const result = scaffoldPlugin(plugin, pm);
				return result.ok ? ok(result.text) : fail(result.message);
			}
			case "generate_schema": {
				const plugins = Array.isArray(args.plugins)
					? args.plugins.filter((p): p is string => typeof p === "string")
					: [];
				const result = await generateSchema({
					plugins,
					agents: args.agents !== false,
					mcp: args.mcp === true,
				});
				return result.ok ? ok(result.text) : fail(result.message);
			}
			case "inspect":
				return ok(JSON.stringify(inspectProject(ctx.cwd), null, 2));
			default:
				return fail(`Unknown tool "${name}".`);
		}
	} catch (err) {
		return fail(`Tool failed: ${err instanceof Error ? err.message : String(err)}`);
	}
}
