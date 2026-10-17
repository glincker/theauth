/**
 * Admin approval flow, end to end: a real theAuth HTTP server with the adminApi
 * plugin, the admin MCP server wired to it, and two human admins.
 */
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
	adminApi,
	agents,
	auditLogs,
	createTheAuth,
	delegationChains,
	users,
} from "@glinr/theauth";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { eq } from "drizzle-orm";
import { ApiClient } from "../../../packages/mcp/src/client.js";
import { createLogger } from "../../../packages/mcp/src/logger.js";
import { createServer } from "../../../packages/mcp/src/server.js";

export interface Narrator {
	step(n: number, text: string): void;
	note(text: string): void;
}

export interface AuditView {
	action: string;
	result: string;
	mcpResult: string | undefined;
	approvalId: string | undefined;
	userId: string;
}

export interface FlowOutcome {
	first: { status: string; approvalId: string };
	delegationAfterFirst: string;
	selfApproval: { status: number; code: string };
	pendingIds: string[];
	approveStatus: number;
	second: { status: string };
	delegationAfterSecond: string;
	replay: { isError: boolean; text: string };
	audit: AuditView[];
}

const ALICE = "user-alice";
const BOB = "user-bob";
const SYSTEM_AGENT = "agent-system";

interface ToolResult {
	isError?: boolean;
	content: Array<{ type: string; text?: string }>;
}

function toolText(result: unknown): string {
	const r = result as ToolResult;
	return r.content[0]?.text ?? "";
}

function parseJson(text: string): Record<string, unknown> {
	const v: unknown = JSON.parse(text);
	return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
}

function str(v: unknown): string {
	return typeof v === "string" ? v : "";
}

export async function runAdminApprovalFlow(say: Narrator): Promise<FlowOutcome> {
	say.step(
		1,
		"Start a theAuth server (adminApi on) and seed alice, bob, two agents, one delegation",
	);
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		auth: { session: { secret: "demo-only-session-secret-0123456789abcdef" } },
		plugins: [
			adminApi({
				enabled: true,
				adminUserIds: [ALICE, BOB],
				systemAgentId: SYSTEM_AGENT,
			}),
		],
	});
	const now = new Date();
	for (const [id, name] of [
		[ALICE, "Alice"],
		[BOB, "Bob"],
	] as const) {
		await auth.db.insert(users).values({
			id,
			email: `${name.toLowerCase()}@example.com`,
			name,
			createdAt: now,
			updatedAt: now,
		});
	}
	await auth.db.insert(agents).values({
		id: SYSTEM_AGENT,
		ownerId: ALICE,
		name: "admin-api-system",
		type: "autonomous",
		status: "active",
		tokenHash: "unused",
		tokenPrefix: "unused",
		createdAt: now,
		updatedAt: now,
	});
	const from = await auth.agent.create({
		ownerId: ALICE,
		name: "orchestrator",
		type: "autonomous",
		permissions: [{ resource: "mcp:crm:notes", actions: ["read"] }],
	});
	const to = await auth.agent.create({
		ownerId: ALICE,
		name: "worker",
		type: "delegated",
		permissions: [],
	});
	const chain = await auth.delegate({
		fromAgent: from.id,
		toAgent: to.id,
		permissions: [{ resource: "mcp:crm:notes", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		maxDepth: 1,
	});
	const session = auth.auth.session;
	if (!session) throw new Error("session manager missing");
	const aliceToken = (await session.create(ALICE)).token;
	const bobToken = (await session.create(BOB)).token;

	const http = createHttpServer((req, res) => {
		void (async () => {
			const chunks: Buffer[] = [];
			for await (const c of req) chunks.push(c as Buffer);
			const body = Buffer.concat(chunks);
			const headers = new Headers();
			for (const [k, v] of Object.entries(req.headers)) {
				if (typeof v === "string") headers.set(k, v);
			}
			const method = req.method ?? "GET";
			const request = new Request(`http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`, {
				method,
				headers,
				body: method === "GET" || method === "HEAD" || body.length === 0 ? undefined : body,
			});
			const response =
				(await auth.plugins.handleRequest(request, "/api")) ?? new Response("nf", { status: 404 });
			res.writeHead(response.status, Object.fromEntries(response.headers));
			res.end(Buffer.from(await response.arrayBuffer()));
		})();
	});
	await new Promise<void>((resolve) => http.listen(0, "127.0.0.1", resolve));
	const apiUrl = `http://127.0.0.1:${(http.address() as AddressInfo).port}/api`;
	say.note(`server ${apiUrl}, admins ${ALICE}, ${BOB}; delegation ${chain.id.slice(0, 12)} active`);

	const delegationStatus = async (): Promise<string> => {
		const [row] = await auth.db
			.select()
			.from(delegationChains)
			.where(eq(delegationChains.id, chain.id));
		return row?.status ?? "missing";
	};
	const api = async (token: string, method: string, path: string, body?: unknown) => {
		const res = await fetch(`${apiUrl}${path}`, {
			method,
			headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
			body: body === undefined ? undefined : JSON.stringify(body),
		});
		const parsed: unknown = await res.json().catch(() => ({}));
		return { status: res.status, body: parsed as Record<string, unknown> };
	};

	let mcp: Client | undefined;
	try {
		say.step(2, "Admin MCP (actor alice-mcp, alice's Bearer) calls revoke_delegation");
		const server = createServer(
			new ApiClient({ apiUrl, apiKey: aliceToken, timeoutMs: 5000 }),
			createLogger(() => undefined),
			"0.0.0",
			{ allowWrites: true, actor: "alice-mcp" },
		);
		const [a, b] = InMemoryTransport.createLinkedPair();
		await server.connect(a);
		mcp = new Client({ name: "example", version: "0.0.0" });
		await mcp.connect(b);
		const callRevoke = async (approvalId?: string) =>
			(await mcp?.callTool({
				name: "revoke_delegation",
				arguments: { id: chain.id, reason: "offboarding", ...(approvalId ? { approvalId } : {}) },
			})) as ToolResult;

		const firstRaw = await callRevoke();
		const firstBody = parseJson(toolText(firstRaw));
		const first = { status: str(firstBody.status), approvalId: str(firstBody.approvalId) };
		const delegationAfterFirst = await delegationStatus();
		say.note(
			`status ${first.status}, approvalId ${first.approvalId.slice(0, 12)}, delegation ${delegationAfterFirst}`,
		);

		say.step(3, "Alice tries to approve her own request over HTTP");
		const self = await api(aliceToken, "POST", `/approvals/${first.approvalId}/approve`);
		const selfErr = (self.body.error ?? {}) as Record<string, unknown>;
		const selfApproval = { status: self.status, code: str(selfErr.code) };
		say.note(`HTTP ${selfApproval.status} ${selfApproval.code}`);

		say.step(4, "Bob lists pending approvals and approves");
		const listed = await fetch(`${apiUrl}/approvals?status=pending`, {
			headers: { Authorization: `Bearer ${bobToken}` },
		});
		const pending = (await listed.json()) as Array<Record<string, unknown>>;
		const pendingIds = pending.map((p) => str(p.id));
		say.note(
			`pending: ${pending.map((p) => `${str(p.action)} ${str(p.resource)} by ${str(p.requestedBy)}`).join("; ")}`,
		);
		const approved = await api(bobToken, "POST", `/approvals/${first.approvalId}/approve`);
		say.note(`approve -> HTTP ${approved.status} ${str(approved.body.status)}`);

		say.step(5, "Call revoke_delegation again with the approvalId");
		const secondBody = parseJson(toolText(await callRevoke(first.approvalId)));
		const second = { status: str(secondBody.status) };
		const delegationAfterSecond = await delegationStatus();
		say.note(`status ${second.status}, delegation ${delegationAfterSecond}`);

		say.step(6, "Replay with the same approvalId");
		const replayRaw = await callRevoke(first.approvalId);
		const replay = { isError: replayRaw.isError === true, text: toolText(replayRaw) };
		say.note(
			`refused: ${replay.isError}, ${str(((parseJson(replay.text).error ?? {}) as Record<string, unknown>).code)}`,
		);

		say.step(7, "Audit events written");
		const rows = await auth.db.select().from(auditLogs);
		const audit = rows
			.filter((r) => r.action.startsWith("admin_mcp.") || r.action.startsWith("admin_api."))
			.sort((x, y) => x.timestamp.getTime() - y.timestamp.getTime())
			.map((r) => {
				const p = (r.parameters ?? {}) as Record<string, unknown>;
				return {
					action: r.action,
					result: r.result,
					mcpResult: typeof p.result === "string" ? p.result : undefined,
					approvalId: typeof p.approvalId === "string" ? p.approvalId : undefined,
					userId: r.userId,
				};
			});
		for (const e of audit) {
			say.note(`${e.action} ${e.mcpResult ?? e.result} by ${e.userId}`);
		}
		return {
			first,
			delegationAfterFirst,
			selfApproval,
			pendingIds,
			approveStatus: approved.status,
			second,
			delegationAfterSecond,
			replay,
			audit,
		};
	} finally {
		await mcp?.close();
		http.close();
	}
}
