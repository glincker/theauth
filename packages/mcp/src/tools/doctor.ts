import type { z } from "zod";
import type { ApiClient, ApiResult } from "../client.js";
import { defineTool, success } from "./define.js";

type Status = "pass" | "warn" | "fail" | "skip";

export interface Check {
	name: string;
	status: Status;
	detail: string;
}

const PROBE_AGENT_ID = "theauth-mcp-doctor-probe";

function isLocal(host: string): boolean {
	return (
		host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".local")
	);
}

function codeOf(r: ApiResult): string {
	return r.ok ? "" : r.error.code;
}

export async function runDoctor(client: ApiClient): Promise<{ overall: Status; checks: Check[] }> {
	const checks: Check[] = [];
	const add = (name: string, status: Status, detail: string): void => {
		checks.push({ name, status, detail });
	};

	const url = new URL(client.baseUrl);
	if (url.protocol === "https:") add("transport", "pass", "API URL uses https");
	else if (isLocal(url.hostname))
		add("transport", "warn", "http on a local host, fine for development");
	else
		add(
			"transport",
			"fail",
			"API URL uses plain http on a non-local host; the key is sent in clear text",
		);

	const [meta, resource, agents, audit, probe] = await Promise.all([
		client.request("GET", "/.well-known/oauth-authorization-server"),
		client.request("GET", "/.well-known/oauth-protected-resource"),
		client.request("GET", "/agents", { query: { status: "active" } }),
		client.request("GET", "/audit", { query: { limit: 1 } }),
		client.request("POST", `/agents/${PROBE_AGENT_ID}/simulate`, {
			body: { action: "read", resource: "doctor:probe" },
		}),
	]);

	if (agents.ok) {
		const n = Array.isArray(agents.data) ? agents.data.length : 0;
		add("management_auth", "pass", `GET /agents accepted the key (${n} active agents)`);
	} else if (agents.error.status === 401) {
		add("management_auth", "fail", "GET /agents returned 401: the key was rejected");
	} else if (agents.error.status === 0) {
		add("management_auth", "fail", `${agents.error.message} (${codeOf(agents)})`);
	} else {
		add("management_auth", "fail", `GET /agents failed: ${agents.error.code}`);
	}

	if (audit.ok) add("audit_query", "pass", "GET /audit is queryable");
	else add("audit_query", "fail", `GET /audit failed: ${audit.error.code}`);

	if (meta.ok) add("mcp_oauth_metadata", "pass", "authorization server metadata is served");
	else if (meta.error.status === 404)
		add("mcp_oauth_metadata", "skip", "MCP OAuth module is not configured (404)");
	else add("mcp_oauth_metadata", "warn", `metadata check failed: ${meta.error.code}`);

	if (resource.ok) add("mcp_resource_metadata", "pass", "protected resource metadata is served");
	else if (resource.error.status === 404)
		add("mcp_resource_metadata", "skip", "MCP OAuth module is not configured (404)");
	else add("mcp_resource_metadata", "warn", `metadata check failed: ${resource.error.code}`);

	if (probe.ok) {
		add("simulator", "pass", "simulator endpoint responded");
	} else if (probe.error.code === "SIMULATE_AGENT_NOT_FOUND") {
		add("simulator", "pass", "simulator plugin is mounted (probe agent not found, as expected)");
	} else if (probe.error.status === 403) {
		add(
			"simulator",
			"warn",
			"simulator is mounted but this key is not an admin; check_permission will fail",
		);
	} else if (probe.error.status === 401) {
		add("simulator", "fail", "simulator returned 401: the key was rejected");
	} else {
		add("simulator", "skip", "simulator plugin not detected; check_permission needs it");
	}

	const overall: Status = checks.some((c) => c.status === "fail")
		? "fail"
		: checks.some((c) => c.status === "warn")
			? "warn"
			: "pass";
	return { overall, checks };
}

export const doctor = defineTool({
	name: "doctor",
	title: "Check deployment health",
	description:
		"Sanity-check the configured theAuth deployment: URL transport, whether the key is accepted by the management routes, audit queryability, MCP OAuth metadata and the simulator plugin. Read-only; sends a handful of GET requests and one dry-run simulate probe that writes nothing.",
	inputSchema: {},
	async run(_args: z.objectOutputType<Record<string, never>, z.ZodTypeAny>, { client }) {
		return success(await runDoctor(client));
	},
});
