import { stdout } from "node:process";
import { loadCredential } from "./auth/token-cache.js";
import { resolveServer } from "./auth-commands.js";

export const SIMULATE_HELP = `
theauth simulate | permissions

Usage:
  theauth simulate --agent <id> --action <a> --resource <r> [--ip <ip>] [--json] [--server <url>]
  theauth permissions <agent-id> [--json] [--server <url>]

Asks the server what an agent would be allowed to do. Nothing is recorded:
no audit rows, no rate counters, no spend. You must be signed in as an admin
(theauth login) and the server must mount the simulator() plugin.

simulate prints the decision (allow, deny, needs_approval), the reasons, and
the step by step trace. permissions prints one row per rule and action the
agent holds, with the simulated decision for each.
`;

export interface SimulateArgs {
	agent?: string;
	action?: string;
	resource?: string;
	ip?: string;
	server?: string;
	json: boolean;
	help: boolean;
	error: string | null;
}

export function parseSimulateArgs(
	args: string[],
	command: "simulate" | "permissions",
): SimulateArgs {
	const out: SimulateArgs = { json: false, help: false, error: null };
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const eq = a.indexOf("=");
		const flag = a.startsWith("--") && eq !== -1 ? a.slice(0, eq) : a;
		const inline = a.startsWith("--") && eq !== -1 ? a.slice(eq + 1) : undefined;
		const value = (): string | undefined => inline ?? args[++i];
		if (flag === "--agent") out.agent = value();
		else if (flag === "--action") out.action = value();
		else if (flag === "--resource") out.resource = value();
		else if (flag === "--ip") out.ip = value();
		else if (flag === "--server") out.server = value();
		else if (flag === "--json") out.json = true;
		else if (flag === "--help" || flag === "-h") out.help = true;
		else if (command === "permissions" && !a.startsWith("-") && out.agent === undefined)
			out.agent = a;
		else out.error ??= `Unknown argument: ${a}`;
	}
	if (out.help || out.error !== null) return out;
	if (!out.agent) {
		out.error = command === "simulate" ? "Missing --agent <id>" : "Missing agent id";
	} else if (command === "simulate" && (!out.action || !out.resource)) {
		out.error = "Missing --action and --resource";
	}
	return out;
}

interface Trace {
	stage: string;
	outcome: string;
	detail: string;
}

interface SimulationResponse {
	decision: string;
	reasons: string[];
	trace: Trace[];
}

interface EffectiveRow {
	resource: string;
	action: string;
	source: string;
	chainId?: string;
	decision: string;
	reasons: string[];
}

async function call(
	args: SimulateArgs,
	body: unknown,
): Promise<{ status: number; body: unknown } | string> {
	const server = await resolveServer(args.server, false);
	const cred = await loadCredential(server);
	if (!cred) return `Not logged in to ${server}. Run: theauth login --server ${server}`;
	const res = await fetch(`${server}/agents/${encodeURIComponent(args.agent ?? "")}/simulate`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `${cred.tokenType} ${cred.accessToken}`,
		},
		body: JSON.stringify(body),
	});
	const parsed: unknown = await res.json().catch(() => ({}));
	return { status: res.status, body: parsed };
}

function describeFailure(status: number, body: unknown): string {
	const b = (body ?? {}) as { error?: string; error_description?: string };
	if (status === 401) return "Your session is not valid. Run: theauth login";
	if (status === 403) return "Admin access required to simulate.";
	if (status === 404 && !b.error) return "The server does not mount the simulator() plugin.";
	return `Server error (${status}): ${b.error_description ?? b.error ?? "unknown"}`;
}

export function renderTable(headers: string[], rows: string[][]): string {
	const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
	const line = (cells: string[]) =>
		cells
			.map((c, i) => c.padEnd(widths[i] ?? 0))
			.join("  ")
			.trimEnd();
	return [line(headers), line(widths.map((w) => "-".repeat(w))), ...rows.map(line)].join("\n");
}

export async function runSimulate(args: SimulateArgs): Promise<number> {
	const result = await call(args, {
		action: args.action,
		resource: args.resource,
		context: args.ip ? { ip: args.ip } : undefined,
	});
	if (typeof result === "string") {
		stdout.write(`${result}\n`);
		return 1;
	}
	if (result.status !== 200) {
		stdout.write(`${describeFailure(result.status, result.body)}\n`);
		return 1;
	}
	const data = result.body as SimulationResponse;
	if (args.json) {
		stdout.write(`${JSON.stringify(data, null, 2)}\n`);
	} else {
		stdout.write(`Decision: ${data.decision}\n`);
		for (const r of data.reasons) stdout.write(`Reason: ${r}\n`);
		stdout.write("\nTrace:\n");
		for (const [i, s] of data.trace.entries()) {
			stdout.write(`  ${i + 1}. [${s.stage}] ${s.outcome}: ${s.detail}\n`);
		}
	}
	return data.decision === "allow" ? 0 : 2;
}

export async function runPermissions(args: SimulateArgs): Promise<number> {
	const result = await call(args, { effective: true });
	if (typeof result === "string") {
		stdout.write(`${result}\n`);
		return 1;
	}
	if (result.status !== 200) {
		stdout.write(`${describeFailure(result.status, result.body)}\n`);
		return 1;
	}
	const data = result.body as { agentId: string; permissions: EffectiveRow[] };
	if (args.json) {
		stdout.write(`${JSON.stringify(data, null, 2)}\n`);
		return 0;
	}
	if (data.permissions.length === 0) {
		stdout.write(`Agent ${data.agentId} holds no permissions.\n`);
		return 0;
	}
	stdout.write(
		`${renderTable(
			["RESOURCE", "ACTION", "SOURCE", "DECISION"],
			data.permissions.map((p) => [
				p.resource,
				p.action,
				p.chainId ? `${p.source}:${p.chainId}` : p.source,
				p.decision,
			]),
		)}\n`,
	);
	return 0;
}
