/**
 * `theauth approvals`: list, show, approve, deny and request, over the admin API plugin.
 * The commands call the HTTP routes (`/approvals`), so they work against any running
 * server that mounts `adminApi`, with an admin user token.
 */

import { stdout } from "node:process";
import { loadCredential } from "./auth/token-cache.js";
import { resolveServer } from "./auth-commands.js";

export const APPROVALS_HELP = `
theauth approvals

Usage:
  theauth approvals list [--limit <n>] [--json]
  theauth approvals show <id> [--json]
  theauth approvals approve <id> [--json]
  theauth approvals deny <id> [--json]
  theauth approvals request --action admin:<name> --resource <resource>
                            [--args <json>] [--required-approvals <1-10>] [--json]

Options:
  --server <url>            Where TheAuth is mounted (default: $THEAUTH_URL, else the only
                            server you are logged in to).
  --token <token>           Admin user token (default: $THEAUTH_ADMIN_TOKEN, else the saved
                            login from "theauth login").
  --required-approvals <n>  request only. Distinct approvers needed, none of them the
                            requester (default 1). The request stays pending until n
                            different admins approve it. One denial ends it.
  --json                    Machine readable output.

The admin API plugin must be enabled on the server. Approving needs an admin who is not
the requester, and the server may ask for a fresh sign-in (step-up, RFC 9470).
`;

type Sub = "list" | "show" | "approve" | "deny" | "request";
const SUBS: readonly Sub[] = ["list", "show", "approve", "deny", "request"];

export interface ApprovalsArgs {
	sub?: Sub;
	id?: string;
	server?: string;
	token?: string;
	limit?: number;
	action?: string;
	resource?: string;
	args?: Record<string, unknown>;
	requiredApprovals?: number;
	json: boolean;
	help: boolean;
	error: string | null;
}

function intInRange(value: string | undefined, min: number, max: number): number | null {
	if (value === undefined || !/^\d+$/.test(value)) return null;
	const n = Number(value);
	return n >= min && n <= max ? n : null;
}

export function parseApprovalsArgs(argv: string[]): ApprovalsArgs {
	const out: ApprovalsArgs = { json: false, help: false, error: null };
	const [sub, ...rest] = argv;
	if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") {
		out.help = true;
		return out;
	}
	if (!(SUBS as readonly string[]).includes(sub)) {
		out.error = `Unknown approvals command: ${sub}`;
		return out;
	}
	out.sub = sub as Sub;
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		const eq = a.startsWith("--") ? a.indexOf("=") : -1;
		const flag = eq > 0 ? a.slice(0, eq) : a;
		const next = (): string | undefined => (eq > 0 ? a.slice(eq + 1) : rest[++i]);
		switch (flag) {
			case "--json":
				out.json = true;
				break;
			case "--help":
			case "-h":
				out.help = true;
				break;
			case "--server":
				out.server = next();
				break;
			case "--token":
				out.token = next();
				break;
			case "--action":
				out.action = next();
				break;
			case "--resource":
				out.resource = next();
				break;
			case "--limit": {
				const n = intInRange(next(), 1, 100);
				if (n === null) out.error ??= "--limit must be an integer from 1 to 100";
				else out.limit = n;
				break;
			}
			case "--required-approvals": {
				const n = intInRange(next(), 1, 10);
				if (n === null) out.error ??= "--required-approvals must be an integer from 1 to 10";
				else out.requiredApprovals = n;
				break;
			}
			case "--args": {
				try {
					const parsed: unknown = JSON.parse(next() ?? "");
					if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
						throw new Error("not an object");
					}
					out.args = parsed as Record<string, unknown>;
				} catch {
					out.error ??= "--args must be a JSON object";
				}
				break;
			}
			default:
				if (a.startsWith("-")) out.error ??= `Unknown option: ${a}`;
				else if (out.id === undefined) out.id = a;
				else out.error ??= `Unexpected argument: ${a}`;
		}
	}
	if (out.error === null) {
		if ((out.sub === "show" || out.sub === "approve" || out.sub === "deny") && !out.id) {
			out.error = `approvals ${out.sub} needs an approval id`;
		}
		if (out.sub === "request" && (!out.action || !out.resource)) {
			out.error = "approvals request needs --action and --resource";
		}
		if (out.sub === "request" && out.action && !/^admin:\S+$/.test(out.action)) {
			out.error = "--action must look like admin:<name>";
		}
		if (out.sub !== "request" && out.requiredApprovals !== undefined) {
			out.error = "--required-approvals only applies to approvals request";
		}
	}
	return out;
}

export interface ApprovalsDeps {
	fetch?: typeof fetch;
	write?: (text: string) => void;
}

interface Row {
	[key: string]: unknown;
}

function unwrap(body: unknown): unknown {
	if (body && typeof body === "object" && !Array.isArray(body)) {
		const o = body as Row;
		if ("data" in o && !("id" in o)) return o.data;
	}
	return body;
}

function progress(r: Row): string {
	const need = typeof r.requiredApprovals === "number" ? r.requiredApprovals : 1;
	const got = typeof r.approvalsReceived === "number" ? r.approvalsReceived : 0;
	return `${got} of ${need}`;
}

function describe(r: Row): string[] {
	const lines = [
		`${String(r.id)}  ${r.status === undefined ? "" : `${String(r.status)}  `}${String(r.action)} on ${String(r.resource)}`,
	];
	if (r.requiredApprovals !== undefined) lines.push(`  approvals: ${progress(r)}`);
	if (Array.isArray(r.approvers) && r.approvers.length > 0) {
		lines.push(`  approved by: ${r.approvers.join(", ")}`);
	}
	if (r.requestedBy !== undefined) lines.push(`  requested by: ${String(r.requestedBy)}`);
	if (r.expiresAt !== undefined) lines.push(`  expires: ${String(r.expiresAt)}`);
	return lines;
}

async function credentials(
	args: ApprovalsArgs,
): Promise<{ base: string; authorization: string } | string> {
	const base = await resolveServer(args.server, false);
	const explicit = args.token ?? process.env.THEAUTH_ADMIN_TOKEN;
	if (explicit) return { base, authorization: `Bearer ${explicit}` };
	const cred = await loadCredential(base);
	if (!cred) {
		return `Not logged in to ${base}. Run: theauth login --server ${base}, or pass --token.`;
	}
	return { base, authorization: `${cred.tokenType} ${cred.accessToken}` };
}

/** Returns the process exit code. */
export async function runApprovals(args: ApprovalsArgs, deps: ApprovalsDeps = {}): Promise<number> {
	const write = deps.write ?? ((t: string) => void stdout.write(t));
	const doFetch = deps.fetch ?? fetch;
	let creds: Awaited<ReturnType<typeof credentials>>;
	try {
		creds = await credentials(args);
	} catch (err) {
		write(`${err instanceof Error ? err.message : String(err)}\n`);
		return 1;
	}
	if (typeof creds === "string") {
		write(`${creds}\n`);
		return 1;
	}

	let method = "GET";
	let path = "/approvals";
	let body: string | undefined;
	switch (args.sub) {
		case "list":
			path = `/approvals?status=pending${args.limit ? `&limit=${args.limit}` : ""}`;
			break;
		case "show":
			path = `/approvals/${encodeURIComponent(args.id ?? "")}`;
			break;
		case "approve":
		case "deny":
			method = "POST";
			path = `/approvals/${encodeURIComponent(args.id ?? "")}/${args.sub}`;
			break;
		case "request":
			method = "POST";
			body = JSON.stringify({
				action: args.action,
				resource: args.resource,
				...(args.args ? { arguments: args.args } : {}),
				...(args.requiredApprovals !== undefined
					? { requiredApprovals: args.requiredApprovals }
					: {}),
			});
			break;
		default:
			return 1;
	}

	const headers: Record<string, string> = { authorization: creds.authorization };
	if (body !== undefined) headers["content-type"] = "application/json";
	let res: Response;
	try {
		res = await doFetch(`${creds.base}${path}`, { method, headers, body });
	} catch (err) {
		write(`Could not reach ${creds.base}: ${err instanceof Error ? err.message : String(err)}\n`);
		return 1;
	}
	const text = await res.text();
	let parsed: unknown;
	try {
		parsed = text ? JSON.parse(text) : null;
	} catch {
		parsed = null;
	}
	if (!res.ok) {
		const e = (parsed as { error?: { code?: string; message?: string } } | null)?.error;
		const reason = e?.message ?? `HTTP ${res.status}`;
		write(`${e?.code ? `${e.code}: ` : ""}${reason}\n`);
		if (res.status === 401 && res.headers.get("www-authenticate")?.includes("insufficient_user")) {
			write("The server wants a fresher sign-in. Run: theauth login, then retry.\n");
		}
		return 1;
	}

	const data = unwrap(parsed);
	if (args.json) {
		write(`${JSON.stringify(data, null, 2)}\n`);
		return 0;
	}
	if (args.sub === "list") {
		const rows = Array.isArray(data) ? (data as Row[]) : [];
		if (rows.length === 0) write("No pending approvals.\n");
		for (const r of rows) write(`${describe(r).join("\n")}\n`);
		return 0;
	}
	const r = (data ?? {}) as Row;
	if (args.sub === "approve" || args.sub === "deny") {
		const done = r.status === "pending" ? `counted, ${progress(r)} approvals` : String(r.status);
		write(`${String(r.id)}: ${done}\n`);
		return 0;
	}
	write(`${describe(r).join("\n")}\n`);
	return 0;
}
