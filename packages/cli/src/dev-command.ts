/**
 * `theauth dev`: zero-config local first run.
 */

import { env, stdout } from "node:process";
import type { TheAuth } from "@glinr/theauth";
import { createAuditModule, createTheAuth, users } from "@glinr/theauth";
import type { DemoServerHandle } from "./demo-server.js";
import { startDemoServer } from "./demo-server.js";

export const DEV_HELP = `
Usage:
  theauth dev [--port <n>] [--smoke]

Starts a local in-memory theauth server with a demo user, two agents, a
delegation and a policy check, then prints a short walkthrough.

Options:
  --port <n>   Port to listen on (env THEAUTH_DEV_PORT, default 3100)
  --smoke      Run the walkthrough, check the server answers, then exit
  --help, -h   Show this help
`;

export const DEFAULT_DEV_PORT = 3100;

export interface DevArgs {
	port: number;
	smoke: boolean;
	help: boolean;
	error: string | null;
}

export function parseDevArgs(args: string[], environment: NodeJS.ProcessEnv = env): DevArgs {
	const out: DevArgs = { port: DEFAULT_DEV_PORT, smoke: false, help: false, error: null };
	const fromEnv = environment.THEAUTH_DEV_PORT;
	let portText: string | undefined = fromEnv !== undefined && fromEnv !== "" ? fromEnv : undefined;
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		if (a === "--help" || a === "-h") out.help = true;
		else if (a === "--smoke") out.smoke = true;
		else if (a === "--port") portText = args[++i] ?? "";
		else if (a.startsWith("--port=")) portText = a.slice("--port=".length);
		else if (out.error === null) out.error = `Unknown option: ${a}`;
	}
	if (portText !== undefined) {
		const n = Number(portText);
		if (!Number.isInteger(n) || n < 1 || n > 65535) out.error = `Invalid port: ${portText}`;
		else out.port = n;
	}
	return out;
}

export interface ToolCallOutcome {
	label: string;
	agent: string;
	action: string;
	resource: string;
	allowed: boolean;
	reason: string | null;
}

export interface DevWorkspace {
	userEmail: string;
	plannerId: string;
	workerId: string;
	calls: ToolCallOutcome[];
	auditRows: number;
	chainOk: boolean;
}

export const DEV_USER_ID = "user-demo";
export const DEV_USER_EMAIL = "demo@theauth.dev";

export function createDevInstance(): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 50,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
}

export async function seedDevWorkspace(theauth: TheAuth): Promise<DevWorkspace> {
	theauth.db
		.insert(users)
		.values({
			id: DEV_USER_ID,
			email: DEV_USER_EMAIL,
			name: "Demo User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	const planner = await theauth.agent.create({
		ownerId: DEV_USER_ID,
		name: "planner-agent",
		type: "autonomous",
		permissions: [
			{ resource: "mcp:github:repos", actions: ["read", "list"] },
			{ resource: "mcp:github:issues", actions: ["read", "list", "write"] },
		],
	});
	const worker = await theauth.agent.create({
		ownerId: DEV_USER_ID,
		name: "worker-agent",
		type: "delegated",
		permissions: [],
	});

	// The user's planner hands the worker one narrow slice: read repos, nothing else.
	await theauth.delegate({
		fromAgent: planner.id,
		toAgent: worker.id,
		permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
		maxDepth: 1,
	});

	const plan = [
		{
			label: "Read a repo (inside the delegation)",
			agent: worker,
			action: "read",
			resource: "mcp:github:repos",
		},
		{
			label: "Delete a repo (outside the delegation)",
			agent: worker,
			action: "delete",
			resource: "mcp:github:repos",
		},
		{
			label: "Comment on an issue (planner's own grant)",
			agent: planner,
			action: "write",
			resource: "mcp:github:issues",
		},
	];
	const calls: ToolCallOutcome[] = [];
	for (const step of plan) {
		const r = await theauth.authorize(step.agent.id, {
			action: step.action,
			resource: step.resource,
		});
		calls.push({
			label: step.label,
			agent: step.agent.name,
			action: step.action,
			resource: step.resource,
			allowed: r.allowed,
			reason: r.reason ?? null,
		});
	}

	const rows = await theauth.audit.query({ limit: 10000 });
	const chain = await createAuditModule({ db: theauth.db }).verifyAuditChain({});
	return {
		userEmail: DEV_USER_EMAIL,
		plannerId: planner.id,
		workerId: worker.id,
		calls,
		auditRows: Array.isArray(rows) ? rows.length : 0,
		chainOk: chain.success && chain.data.ok,
	};
}

export interface WalkthroughUrls {
	dashboard: string | null;
	api: string;
}

/** Plain-text walkthrough. Pure so it can be tested. */
export function formatWalkthrough(ws: DevWorkspace, urls: WalkthroughUrls): string {
	const lines: string[] = [];
	lines.push("", "  theauth dev: local first run", "");
	lines.push(`  1. User        ${ws.userEmail} (seeded)`);
	lines.push("  2. Agents      planner-agent (owned by the user), worker-agent");
	lines.push("  3. Delegation  planner-agent -> worker-agent: read on mcp:github:repos only", "");
	lines.push("  4. Guarded tool calls");
	for (const c of ws.calls) {
		const verdict = c.allowed ? "ALLOWED" : "DENIED ";
		lines.push(`     ${verdict}  ${c.agent}: ${c.action} ${c.resource}`);
		lines.push(`              ${c.label}`);
	}
	lines.push("");
	lines.push(
		`  5. Audit       ${ws.auditRows} entries recorded, hash chain ${ws.chainOk ? "verified" : "BROKEN"}`,
		"",
	);
	if (urls.dashboard !== null) lines.push(`  Dashboard  ${urls.dashboard}`);
	else lines.push("  Dashboard  not built in this install (API only)");
	lines.push(`  API        ${urls.api}`);
	lines.push("  Database   in-memory, gone when you stop", "");
	return `${lines.join("\n")}\n`;
}

export async function runDev(args: DevArgs): Promise<number> {
	const theauth = await createDevInstance();
	const ws = await seedDevWorkspace(theauth);

	let handle: DemoServerHandle;
	try {
		handle = await startDemoServer({
			port: args.port,
			theauth,
			quiet: true,
			hostname: "127.0.0.1",
		});
	} catch (err) {
		const code = (err as NodeJS.ErrnoException).code;
		stdout.write(
			code === "EADDRINUSE"
				? `Port ${args.port} is in use. Try: theauth dev --port ${args.port + 1}\n`
				: `Could not start the server: ${err instanceof Error ? err.message : String(err)}\n`,
		);
		return 1;
	}

	const base = `http://localhost:${handle.port}`;
	stdout.write(
		formatWalkthrough(ws, {
			dashboard: handle.dashboard ? base : null,
			api: `${base}/api`,
		}),
	);

	const expected = ws.calls.some((c) => c.allowed) && ws.calls.some((c) => !c.allowed);
	if (args.smoke) {
		const res = await fetch(`${base}/api/agents`);
		const body = (await res.json()) as unknown;
		await handle.close();
		const ok = res.ok && Array.isArray(body) && body.length === 2 && expected && ws.chainOk;
		stdout.write(ok ? "  Smoke check passed.\n" : "  Smoke check failed.\n");
		return ok ? 0 : 1;
	}

	stdout.write("  Press Ctrl+C to stop.\n\n");
	await new Promise<void>((done) => {
		const stop = () => {
			void handle.close().then(done);
		};
		process.once("SIGINT", stop);
		process.once("SIGTERM", stop);
	});
	return 0;
}
