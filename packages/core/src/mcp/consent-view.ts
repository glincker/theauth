import { resolveClient } from "./client-metadata.js";
import { redirectUriAllowed } from "./lenient.js";
import type { McpAuthContext, McpClient, Result } from "./types.js";
import type { ClientDescription, ConsentWarning } from "./types-cimd.js";

const RECENT_CHANGE_MS = 24 * 60 * 60 * 1000;
/** Domain-like tokens inside a self-asserted name, such as "app.example.com". */
const DOMAIN_TOKEN = /(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/gi;
/** Control, bidi override and zero width characters can disguise a name. Removed by code point. */
function isHidden(code: number): boolean {
	return (
		code <= 0x1f ||
		(code >= 0x7f && code <= 0x9f) ||
		(code >= 0x200b && code <= 0x200f) ||
		(code >= 0x202a && code <= 0x202e) ||
		(code >= 0x2066 && code <= 0x2069) ||
		code === 0xfeff
	);
}

/** True when `host` is `base` or a subdomain of it. */
function sameSite(host: string, base: string): boolean {
	return host === base || host.endsWith(`.${base}`);
}

function hostOf(url: string): string | null {
	try {
		return new URL(url).hostname.toLowerCase().replace(/\.$/, "");
	} catch {
		return null;
	}
}

function isLoopbackHost(host: string): boolean {
	return host === "localhost" || host === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(host);
}

/** Only absolute http(s) URLs are passed on as a logo; anything else (data:, javascript:) is dropped. */
function safeLogoUri(uri: string | null): string | null {
	if (!uri) return null;
	try {
		const url = new URL(uri);
		return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
	} catch {
		return null;
	}
}

function cleanName(name: string | null): string | null {
	if (!name) return null;
	const cleaned = Array.from(name)
		.filter((ch) => !isHidden(ch.codePointAt(0) ?? 0))
		.join("")
		.trim()
		.slice(0, 200);
	return cleaned.length > 0 ? cleaned : null;
}

function sourceOf(ctx: McpAuthContext, client: McpClient): ClientDescription["source"] {
	if (client.source === "cimd") return "cimd";
	const pre = ctx.config.preRegisteredClients ?? [];
	return pre.some((p) => p.clientId === client.clientId) ? "preregistered" : "dcr";
}

interface WarningInput {
	client: McpClient;
	verifiedHost: string | null;
	redirectUri: string;
	redirectHost: string;
	name: string | null;
	firstUse: boolean;
}

function warningsFor(input: WarningInput, now: number): ConsentWarning[] {
	const { client, verifiedHost, redirectUri, redirectHost, name } = input;
	const out: ConsentWarning[] = [];
	if (isLoopbackHost(redirectHost)) out.push("localhost_redirect");
	if (redirectUri.toLowerCase().startsWith("http:")) out.push("http_redirect");
	if (verifiedHost !== null) {
		if (!sameSite(redirectHost, verifiedHost) && !isLoopbackHost(redirectHost)) {
			out.push("redirect_host_differs");
		}
		if (verifiedHost.split(".").some((label) => label.startsWith("xn--"))) out.push("idn_host");
		const mentioned = (name ?? "").match(DOMAIN_TOKEN) ?? [];
		if (mentioned.some((t) => !sameSite(t.toLowerCase(), verifiedHost))) {
			out.push("name_mentions_other_host");
		}
		const uriHost = client.clientUri ? hostOf(client.clientUri) : null;
		if (client.clientUri && (uriHost === null || !sameSite(uriHost, verifiedHost))) {
			out.push("client_uri_host_differs");
		}
		const changedAt = client.updatedAt.getTime();
		if (
			changedAt - client.createdAt.getTime() > 1000 &&
			now - changedAt >= 0 &&
			now - changedAt < RECENT_CHANGE_MS
		) {
			out.push("recently_changed");
		}
	}
	if (client.agentId) out.push("bound_to_agent");
	if (input.firstUse) out.push("first_use");
	return out;
}

/**
 * The facts a consent page must show for a client. For a Client ID Metadata Document client the verified identity is the client_id host (an ASCII hostname); `clientName` and `logoUri` are whatever the client author wrote and are secondary, untrusted display data. The server never fetches `logoUri`.
 * Fails with INVALID_CLIENT for unknown, blocked or disabled clients and INVALID_REDIRECT_URI when the URI is not registered.
 */
export async function describeClientForConsent(
	ctx: McpAuthContext,
	clientId: string,
	redirectUri?: string,
	options: { firstUse?: boolean } = {},
): Promise<Result<ClientDescription>> {
	const client = await resolveClient(ctx, clientId);
	if (!client || client.disabled) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Unknown or disabled client" },
		};
	}
	const chosen = redirectUri ?? client.redirectUris[0];
	if (chosen === undefined || !redirectUriAllowed(ctx, client, chosen)) {
		return {
			success: false,
			error: {
				code: "INVALID_REDIRECT_URI",
				message: "redirect_uri does not match any registered redirect URI",
			},
		};
	}
	const source = sourceOf(ctx, client);
	const verifiedHost = source === "cimd" ? hostOf(client.clientId) : null;
	const redirectHost = hostOf(chosen) ?? "";
	const clientName = cleanName(client.clientName);
	return {
		success: true,
		data: {
			clientId: client.clientId,
			source,
			verifiedHost,
			clientName,
			logoUri: safeLogoUri(client.logoUri),
			redirectUri: chosen,
			redirectHost,
			agentId: client.agentId ?? null,
			warnings: warningsFor(
				{
					client,
					verifiedHost,
					redirectUri: chosen,
					redirectHost,
					name: clientName,
					firstUse: options.firstUse === true,
				},
				Date.now(),
			),
		},
	};
}
