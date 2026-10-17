/**
 * Flagship example: scoped delegation to an agent, verified by an MCP server.
 *
 *   1. A user (Alice) approves an OAuth 2.1 grant (PKCE) for her agent app.
 *   2. The agent narrows it with RFC 8693 token exchange to a read-only token.
 *   3. The agent calls an MCP server. The server verifies the token with
 *      theAuth, and the call is allowed (scope mcp:read).
 *   4. theauth.explain() says why a write would be denied, then the agent tries
 *      the write tool and is denied (scope mcp:write missing).
 *   5. A beforeAuthorize hook receives the delegation chain and blocks a
 *      blocklisted resource. The block leaves an audit row with a decision code.
 *   6. The audit log is printed in write order.
 *   7. Alice revokes the parent delegation (a delegation.revoke audit row names
 *      her). The same token is rejected on the agent's next call, because the
 *      server re-checks the delegation chain.
 *
 * Run with:  pnpm --filter @glinr/theauth-example-agent-delegation-e2e start
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createTheAuth, recordAuditEvent } from "@glinr/theauth";
import type {
	McpAccessToken,
	McpAuthorizationCode,
	McpClient,
	McpSession,
} from "@glinr/theauth/mcp";
import {
	createDbDelegationStore,
	createInMemoryJtiDenylist,
	createMcpModule,
} from "@glinr/theauth/mcp";

const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const REDIRECT_URI = "http://127.0.0.1/callback";
const SIGNING_SECRET = "agent-delegation-e2e-secret-at-least-32-chars-long";
const OWNER_ID = "user-alice";
/** Example blocklist for the beforeAuthorize hook: last segment of the resource. */
const BLOCKED_RESOURCES = new Set(["payroll"]);

/** MCP tools and the OAuth scope each one needs. */
const TOOL_SCOPES: Record<string, string> = {
	read_report: "mcp:read",
	delete_report: "mcp:write",
};

function header(text: string): void {
	console.log(`\n== ${text}`);
}

function line(label: string, value: string): void {
	console.log(`   ${label.padEnd(22)} ${value}`);
}

function short(id: string): string {
	return `${id.slice(0, 12)}...`;
}

function b64url(input: Buffer): string {
	return input.toString("base64url");
}

/** Read the `act.client_id` claim without verifying the signature. Used only to attribute a rejected call in the audit log, never to grant access. */
function unverifiedActorClient(token: string): string | undefined {
	try {
		const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()) as {
			act?: { client_id?: string };
		};
		return payload.act?.client_id;
	} catch {
		return undefined;
	}
}

async function main(): Promise<void> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		hooks: {
			// Fail closed: a throw or timeout here denies the call. It receives the delegation chain.
			async beforeAuthorize({ delegation, resource, source, dryRun }) {
				const depth = delegation.path.length - 1;
				if (!dryRun) {
					console.log(`   [hook] source=${source} chain depth=${depth} resource=${resource}`);
				}
				if (BLOCKED_RESOURCES.has(resource.split(":").pop() ?? "")) {
					return {
						decision: "deny",
						reason: "resource is on the example blocklist",
						ruleId: "example-blocklist",
					};
				}
				return undefined;
			},
		},
	});

	const owner = await auth.user.create({
		id: OWNER_ID,
		email: "alice@example.com",
		name: "Alice",
	});
	if (owner.id !== OWNER_ID) throw new Error("owner id mismatch");

	// ---- Step 0: agents and the delegation between them ----
	header("Setup: owner, agents and delegation");
	const assistant = await auth.agent.create({
		ownerId: OWNER_ID,
		name: "alice-assistant",
		type: "autonomous",
		permissions: [{ resource: "mcp:reports:*", actions: ["read", "write"] }],
	});
	const reportBot = await auth.agent.create({
		ownerId: OWNER_ID,
		name: "report-bot",
		type: "delegated",
		permissions: [],
	});
	const chain = await auth.delegate({
		fromAgent: assistant.id,
		toAgent: reportBot.id,
		permissions: [{ resource: "mcp:reports:*", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		maxDepth: 1,
	});
	line("parent agent", `${assistant.name} (${short(assistant.id)})`);
	line("child agent", `${reportBot.name} (${short(reportBot.id)})`);
	line("delegation", `${short(chain.id)} read on mcp:reports:*`);

	// ---- OAuth 2.1 server + MCP resource server (in-memory stores) ----
	const clients = new Map<string, McpClient>();
	const codes = new Map<string, McpAuthorizationCode>();
	const tokens = new Map<string, McpAccessToken>();
	const refresh = new Map<string, McpAccessToken>();
	/** OAuth client id of the agent app -> agent id. theAuth has no built-in link, so the host supplies it. */
	const agentByClient = new Map<string, string>();

	// The MCP server listens first so the OAuth resource URL can use its real port.
	// biome-ignore lint/style/useConst: assigned after the server is listening
	let mcp: ReturnType<typeof createMcpModule> | undefined;

	async function audit(
		agentId: string,
		tool: string,
		result: "allowed" | "denied",
		reason: string,
		session?: McpSession,
	): Promise<void> {
		await recordAuditEvent(auth.db, {
			agentId,
			action: "mcp.tools.call",
			resource: `mcp:reports:${tool}`,
			result,
			reason,
			...(session ? { subjectId: session.userId, actorId: session.clientId } : {}),
			delegationChain: [assistant.id, agentId],
		});
	}

	const server = createServer((req, res) => {
		void (async () => {
			const send = (status: number, body: unknown): void => {
				res.writeHead(status, { "Content-Type": "application/json" });
				res.end(JSON.stringify(body));
			};
			const chunks: Buffer[] = [];
			for await (const chunk of req) chunks.push(chunk as Buffer);
			const body = JSON.parse(Buffer.concat(chunks).toString() || "{}") as { tool?: string };
			const tool = body.tool ?? "";
			const scope = TOOL_SCOPES[tool];
			if (!mcp || !scope) return send(404, { error: `unknown tool ${tool}` });

			const bearer = (req.headers.authorization ?? "").replace(/^Bearer /, "");
			const request = new Request("http://mcp.local/tools/call", {
				method: "POST",
				headers: { authorization: `Bearer ${bearer}` },
			});
			const check = await mcp.requireScopes(request, [scope]);
			if (!check.authorized) {
				const text = await check.response.text();
				const message =
					(JSON.parse(text) as { error?: { message?: string } }).error?.message ??
					"insufficient scope";
				const clientId = unverifiedActorClient(bearer);
				const agentId = clientId ? agentByClient.get(clientId) : undefined;
				if (agentId) {
					const reason =
						check.response.status === 401 ? `token rejected: ${message}` : `missing scope ${scope}`;
					await audit(agentId, tool, "denied", reason);
				}
				return send(check.response.status, { error: message, status: check.response.status });
			}
			const agentId = agentByClient.get(check.session.clientId);
			if (agentId) await audit(agentId, tool, "allowed", `scope ${scope} granted`, check.session);
			return send(200, { content: `[simulated] ${tool} ok` });
		})().catch((error: unknown) => {
			res.writeHead(500);
			res.end(String(error));
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

	mcp = createMcpModule({
		config: {
			enabled: true,
			issuer: origin,
			baseUrl: `${origin}/api/auth`,
			resource: origin,
			signingSecret: SIGNING_SECRET,
			scopes: ["mcp:read", "mcp:write"],
			accessTokenTtl: 3600,
			jtiDenylist: createInMemoryJtiDenylist(),
			tokenExchange: { enabled: true },
			// Re-check the delegation chain against live records on every call.
			delegationStore: createDbDelegationStore(auth.db),
			resolveActorAgentId: ({ sub, clientId }) =>
				clientId ? agentByClient.get(clientId) : sub === OWNER_ID ? assistant.id : undefined,
		},
		storeClient: async (c) => void clients.set(c.clientId, c),
		findClient: async (id) => clients.get(id) ?? null,
		storeAuthorizationCode: async (c) => void codes.set(c.code, c),
		consumeAuthorizationCode: async (code) => {
			const found = codes.get(code) ?? null;
			codes.delete(code);
			return found;
		},
		storeToken: async (t) => {
			tokens.set(t.accessToken, t);
			if (t.refreshToken) refresh.set(t.refreshToken, t);
		},
		findTokenByRefreshToken: async (rt) => refresh.get(rt) ?? null,
		revokeToken: async () => {},
		// Real apps read the signed-in user from the session cookie here.
		resolveUserId: async () => OWNER_ID,
	});

	try {
		// ---- Step 1: Alice delegates a scoped token (authorization code + PKCE) ----
		header("Step 1: Alice approves a scoped OAuth grant for the agent app");
		const registered = await mcp.registerClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code", TOKEN_EXCHANGE],
			token_endpoint_auth_method: "client_secret_basic",
			client_name: "report-bot app",
			scope: "mcp:read mcp:write",
		});
		if (!registered.success) throw new Error(registered.error.message);
		const { client_id: clientId, client_secret: clientSecret } = registered.data;
		if (!clientSecret) throw new Error("expected a client secret");
		agentByClient.set(clientId, reportBot.id);
		const basic = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;

		const verifier = b64url(randomBytes(32));
		const authorizeUrl = new URL(`${origin}/api/auth/mcp/authorize`);
		for (const [k, v] of Object.entries({
			response_type: "code",
			client_id: clientId,
			redirect_uri: REDIRECT_URI,
			scope: "mcp:read mcp:write",
			code_challenge: b64url(createHash("sha256").update(verifier).digest()),
			code_challenge_method: "S256",
			resource: origin,
		}))
			authorizeUrl.searchParams.set(k, v);
		const authorized = await mcp.authorize(new Request(authorizeUrl));
		if (!authorized.success) throw new Error(authorized.error.message);

		const form = (params: Record<string, string>): Request =>
			new Request(`${origin}/api/auth/mcp/token`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basic },
				body: new URLSearchParams(params).toString(),
			});
		const granted = await mcp.token(
			form({
				grant_type: "authorization_code",
				code: authorized.data.code,
				redirect_uri: REDIRECT_URI,
				client_id: clientId,
				code_verifier: verifier,
				resource: origin,
			}),
		);
		if (!granted.success) throw new Error(granted.error.message);
		line("user grant scopes", granted.data.scope);

		const exchanged = await mcp.token(
			form({
				grant_type: TOKEN_EXCHANGE,
				subject_token: granted.data.access_token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "mcp:read",
				resource: origin,
			}),
		);
		if (!exchanged.success) throw new Error(exchanged.error.message);
		const agentToken = exchanged.data.access_token;
		line("agent token scopes", `${exchanged.data.scope} (narrowed by token exchange)`);

		const callTool = async (
			tool: string,
		): Promise<{ status: number; body: Record<string, unknown> }> => {
			const response = await fetch(`${origin}/tools/call`, {
				method: "POST",
				headers: { "Content-Type": "application/json", Authorization: `Bearer ${agentToken}` },
				body: JSON.stringify({ tool }),
			});
			return { status: response.status, body: (await response.json()) as Record<string, unknown> };
		};

		// ---- Step 2: in scope call ----
		header("Step 2: agent calls read_report (needs mcp:read)");
		const readCall = await callTool("read_report");
		line("HTTP", `${readCall.status}`);
		line("result", JSON.stringify(readCall.body));

		// ---- Step 3: explain, then the out of scope call ----
		header("Step 3: why would delete_report be denied? (theauth.explain)");
		const why = await auth.explain(reportBot.id, "write", "mcp:reports:delete_report");
		if (!why.success) throw new Error(why.error.message);
		const explained = why.data;
		line("decision", `${explained.decision} (code ${explained.code})`);
		line("reason", explained.reason);
		const grant = explained.matchedGrant;
		line(
			"matched grant",
			grant
				? `${grant.source} ${grant.permission.resource} [${grant.permission.actions.join(",")}] resource ${grant.resourceMatch}, action ${grant.actionMatch}`
				: "none (no rule matches write on this resource)",
		);

		header("Step 3b: agent calls delete_report (needs mcp:write)");
		const writeCall = await callTool("delete_report");
		line("HTTP", `${writeCall.status}`);
		line("result", JSON.stringify(writeCall.body));

		// ---- Step 4: a beforeAuthorize hook blocks a blocklisted resource ----
		header("Step 4: beforeAuthorize hook (optional guard on theauth.authorize)");
		const hookAllowed = await auth.authorize(reportBot.id, {
			action: "read",
			resource: "mcp:reports:q3",
		});
		line("read q3", `allowed=${hookAllowed.allowed}`);
		const hookBlocked = await auth.authorize(reportBot.id, {
			action: "read",
			resource: "mcp:reports:payroll",
		});
		line("read payroll", `allowed=${hookBlocked.allowed} code=${hookBlocked.code}`);
		line("audit id", short(hookBlocked.auditId));

		// ---- Audit trail ----
		header("Audit log (write order)");
		const printAudit = async (): Promise<void> => {
			// audit.query returns newest first and orders same-second rows by write order, so reversing gives write order.
			const rows = (await auth.audit.query({ agentId: reportBot.id })).reverse();
			for (const e of rows) {
				const code = e.code ? ` [${e.code}]` : "";
				const by =
					e.action === "delegation.revoke" ? ` revokedBy=${String(e.parameters?.revokedBy)}` : "";
				console.log(
					`   ${e.timestamp.toISOString()} ${e.result.padEnd(8)} ${e.action} ${e.resource}${code}${by} (${e.reason ?? ""})`,
				);
			}
			return void verifyOrder(rows.map((e) => e.action));
		};
		/** The rows were written in this order, so the query must return them in it. */
		const expected = [
			"delegation.create",
			"mcp.tools.call",
			"mcp.tools.call",
			"read",
			"read",
			"delegation.revoke",
			"mcp.tools.call",
		];
		const verifyOrder = (actions: string[]): void => {
			const want = expected.slice(0, actions.length);
			line(
				"write order check",
				JSON.stringify(actions) === JSON.stringify(want) ? "ok" : `MISMATCH ${actions.join(",")}`,
			);
		};
		await printAudit();

		// ---- Revocation ----
		header("Revocation: Alice revokes the parent delegation");
		await auth.delegation.revoke(chain.id, { revokedBy: OWNER_ID });
		line("revoked", short(chain.id));
		const afterRevoke = await callTool("read_report");
		line("HTTP", `${afterRevoke.status}`);
		line("result", JSON.stringify(afterRevoke.body));

		header("Audit log after revocation");
		await printAudit();
	} finally {
		server.close();
	}
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
