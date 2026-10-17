/**
 * In-process theauth MCP OAuth server for the conformance test. It wires the real
 * createMcpModule from packages/core to a Node http server using in-memory stores,
 * the same way core's own mcp-flow tests do, so the suite runs over real sockets.
 */
import type { IncomingMessage, Server } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createMcpModule } from "../../core/src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthorizationCode,
	McpClient,
	Result,
} from "../../core/src/mcp/types.js";

export interface RunningServer {
	url: string;
	close(): Promise<void>;
}

const SIGNING_SECRET = "conformance-test-signing-secret-at-least-32-chars";

async function readBody(req: IncomingMessage): Promise<string> {
	const chunks: Uint8Array[] = [];
	for await (const chunk of req) chunks.push(chunk as Uint8Array);
	return Buffer.concat(chunks).toString("utf8");
}

function toRequest(req: IncomingMessage, origin: string, body: string): Request {
	const headers = new Headers();
	for (const [key, value] of Object.entries(req.headers)) {
		if (typeof value === "string") headers.set(key, value);
	}
	const method = req.method ?? "GET";
	const hasBody = method !== "GET" && method !== "HEAD";
	return new Request(new URL(req.url ?? "/", origin), {
		method,
		headers,
		...(hasBody ? { body } : {}),
		redirect: "manual",
	});
}

function oauthError(result: Result<unknown>, status: number): Response | null {
	if (result.success) return null;
	return Response.json(
		{ error: result.error.code.toLowerCase(), error_description: result.error.message },
		{ status, headers: { "Cache-Control": "no-store" } },
	);
}

export async function startTheauthServer(): Promise<RunningServer> {
	const clients = new Map<string, McpClient>();
	const codes = new Map<string, McpAuthorizationCode>();
	const tokens = new Map<string, McpAccessToken>();
	const byRefresh = new Map<string, McpAccessToken>();

	// The port is only known after listen, so the module is built lazily.
	let origin = "";
	let mcp: ReturnType<typeof createMcpModule> | null = null;

	const build = (base: string) =>
		createMcpModule({
			config: {
				enabled: true,
				issuer: base,
				baseUrl: base,
				signingSecret: SIGNING_SECRET,
				resource: `${base}/mcp`,
				loginPage: `${base}/login`,
				scopes: ["mcp:read", "mcp:write"],
				dpop: {},
			},
			storeClient: async (client) => {
				clients.set(client.clientId, client);
			},
			findClient: async (id) => clients.get(id) ?? null,
			storeAuthorizationCode: async (code) => {
				codes.set(code.code, code);
			},
			consumeAuthorizationCode: async (code) => {
				const found = codes.get(code) ?? null;
				codes.delete(code);
				return found;
			},
			storeToken: async (token) => {
				tokens.set(token.accessToken, token);
				if (token.refreshToken) byRefresh.set(token.refreshToken, token);
			},
			findTokenByRefreshToken: async (refresh) => byRefresh.get(refresh) ?? null,
			revokeToken: async (accessToken) => {
				tokens.delete(accessToken);
			},
			resolveUserId: async () => null,
		});

	async function handle(req: Request): Promise<Response> {
		if (!mcp) return new Response("not ready", { status: 503 });
		const url = new URL(req.url);
		switch (`${req.method} ${url.pathname}`) {
			case "GET /.well-known/oauth-authorization-server":
				return Response.json(mcp.getMetadata());
			case "GET /.well-known/oauth-protected-resource":
				return Response.json(mcp.getProtectedResourceMetadata());
			case "POST /mcp/register": {
				const result = await mcp.registerClient(await req.json());
				if (!result.success) {
					return Response.json(
						{ error: "invalid_client_metadata", error_description: result.error.message },
						{ status: 400 },
					);
				}
				return Response.json(result.data, {
					status: 201,
					headers: { "Cache-Control": "no-store" },
				});
			}
			case "GET /mcp/authorize": {
				const result = await mcp.authorize(req);
				if (result.success) return Response.redirect(result.data.redirectUri, 302);
				if (result.error.code === "LOGIN_REQUIRED") {
					return Response.redirect(`${origin}/login`, 302);
				}
				return oauthError(result, 400) as Response;
			}
			case "POST /mcp/token": {
				const result = await mcp.token(req);
				if (result.success) {
					return Response.json(result.data, { headers: { "Cache-Control": "no-store" } });
				}
				return oauthError(result, result.error.code === "INVALID_CLIENT" ? 401 : 400) as Response;
			}
			case "GET /login":
				return new Response("<html>login</html>", { headers: { "Content-Type": "text/html" } });
			case "POST /mcp": {
				const protectedHandler = mcp.requireMcpAuth(async () => Response.json({ ok: true }), {
					resourceMetadataUrl: `${origin}/.well-known/oauth-protected-resource`,
				});
				return protectedHandler(req);
			}
			default:
				return new Response("not found", { status: 404 });
		}
	}

	const server: Server = createServer((req, res) => {
		void (async () => {
			try {
				const body = await readBody(req);
				const response = await handle(toRequest(req, origin, body));
				res.statusCode = response.status;
				response.headers.forEach((value, key) => {
					res.setHeader(key, value);
				});
				res.end(Buffer.from(await response.arrayBuffer()));
			} catch (error) {
				res.statusCode = 500;
				res.end(error instanceof Error ? error.message : "error");
			}
		})();
	});

	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	origin = `http://127.0.0.1:${port}`;
	mcp = build(origin);

	return {
		url: origin,
		close: () =>
			new Promise<void>((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
				server.closeAllConnections();
			}),
	};
}
