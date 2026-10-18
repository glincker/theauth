/** HTTP route dispatcher for the SSO endpoints. */

import type { SsoModule } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";

export function createSsoRouteHandler(
	ctx: Pick<
		SsoModule,
		| "createConnection"
		| "listConnections"
		| "removeConnection"
		| "getSamlAuthUrl"
		| "handleSamlResponse"
		| "getOidcAuthUrl"
		| "handleOidcCallback"
	>,
): SsoModule["handleRequest"] {
	const {
		createConnection,
		listConnections,
		removeConnection,
		getSamlAuthUrl,
		handleSamlResponse,
		getOidcAuthUrl,
		handleOidcCallback,
	} = ctx;

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const { method } = request;

		const json = (data: unknown, status = 200) =>
			new Response(JSON.stringify(data), {
				status,
				headers: { "Content-Type": "application/json" },
			});

		if (method === "POST" && pathname === "/auth/sso/connections") {
			let body: unknown;
			try {
				body = await request.json();
			} catch {
				return json({ error: "Invalid JSON body" }, 400);
			}
			const b = body as Record<string, unknown>;
			if (
				typeof b.orgId !== "string" ||
				typeof b.providerId !== "string" ||
				typeof b.type !== "string" ||
				typeof b.domain !== "string"
			) {
				return json({ error: "Missing required fields: orgId, providerId, type, domain" }, 400);
			}
			if (b.type !== "saml" && b.type !== "oidc") {
				return json({ error: "type must be 'saml' or 'oidc'" }, 400);
			}
			const conn = await createConnection({
				orgId: b.orgId,
				providerId: b.providerId,
				type: b.type,
				domain: b.domain,
			});
			return json(conn, 201);
		}

		const listMatch = /^\/auth\/sso\/connections\/([^/]+)$/.exec(pathname);
		if (method === "GET" && listMatch) {
			const orgId = decodeURIComponent(listMatch[1] ?? "");
			const conns = await listConnections(orgId);
			return json(conns);
		}

		const deleteMatch = /^\/auth\/sso\/connections\/([^/]+)$/.exec(pathname);
		if (method === "DELETE" && deleteMatch) {
			const connId = decodeURIComponent(deleteMatch[1] ?? "");
			await removeConnection(connId);
			return json({ success: true });
		}

		const samlInitMatch = /^\/auth\/sso\/saml\/([^/]+)$/.exec(pathname);
		if (method === "GET" && samlInitMatch) {
			const connId = decodeURIComponent(samlInitMatch[1] ?? "");
			const relayState = url.searchParams.get("relayState") ?? undefined;
			try {
				const authUrl = await getSamlAuthUrl(connId, relayState);
				return new Response(null, { status: 302, headers: { Location: authUrl } });
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 400);
			}
		}

		const samlAcsMatch = /^\/auth\/sso\/saml\/([^/]+)\/acs$/.exec(pathname);
		if (method === "POST" && samlAcsMatch) {
			const connId = decodeURIComponent(samlAcsMatch[1] ?? "");
			let samlResponse: string;
			try {
				const formData = await request.formData();
				const val = formData.get("SAMLResponse");
				if (typeof val !== "string") throw new Error("Missing SAMLResponse");
				samlResponse = val;
			} catch {
				return json({ error: "Missing or invalid SAMLResponse" }, 400);
			}
			try {
				const result = await handleSamlResponse(connId, samlResponse);
				return json(result);
			} catch (err) {
				const status = err instanceof SsoError && err.code === SSO_ERROR.RATE_LIMITED ? 429 : 401;
				return json(
					{
						error: err instanceof Error ? err.message : "SAML error",
						code: err instanceof SsoError ? err.code : "SAML_ERROR",
					},
					status,
				);
			}
		}

		const oidcInitMatch = /^\/auth\/sso\/oidc\/([^/]+)$/.exec(pathname);
		if (method === "GET" && oidcInitMatch) {
			const connId = decodeURIComponent(oidcInitMatch[1] ?? "");
			const state = url.searchParams.get("state") ?? undefined;
			const nonce = url.searchParams.get("nonce") ?? undefined;
			try {
				const authUrl = await getOidcAuthUrl(connId, state, nonce);
				return new Response(null, { status: 302, headers: { Location: authUrl } });
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 400);
			}
		}

		const oidcCbMatch = /^\/auth\/sso\/oidc\/([^/]+)\/callback$/.exec(pathname);
		if (method === "GET" && oidcCbMatch) {
			const connId = decodeURIComponent(oidcCbMatch[1] ?? "");
			const code = url.searchParams.get("code");
			if (!code) return json({ error: "Missing code parameter" }, 400);
			try {
				const result = await handleOidcCallback(connId, code);
				return json(result);
			} catch (err) {
				const status = err instanceof SsoError && err.code === SSO_ERROR.RATE_LIMITED ? 429 : 401;
				return json(
					{
						error: err instanceof Error ? err.message : "OIDC error",
						code: err instanceof SsoError ? err.code : "OIDC_ERROR",
					},
					status,
				);
			}
		}

		return null;
	}

	return handleRequest;
}
