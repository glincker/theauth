import type { ActionResult, SocialSignInConfig, TheAuthSession } from "./types.js";

function base64url(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function defaultRandomBytes(length: number): Promise<Uint8Array> {
	const out = new Uint8Array(length);
	crypto.getRandomValues(out);
	return out;
}

async function defaultSha256(input: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
}

/** Parse `a=1&b=2` without relying on the React Native URL implementation. */
function parseParams(raw: string): Record<string, string> {
	const out: Record<string, string> = {};
	for (const pair of raw.split("&")) {
		if (!pair) continue;
		const eq = pair.indexOf("=");
		const key = decodeURIComponent((eq === -1 ? pair : pair.slice(0, eq)).replace(/\+/g, " "));
		out[key] = eq === -1 ? "" : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, " "));
	}
	return out;
}

function splitReturnUrl(url: string): {
	query: Record<string, string>;
	fragment: Record<string, string>;
} {
	const hash = url.indexOf("#");
	const beforeHash = hash === -1 ? url : url.slice(0, hash);
	const q = beforeHash.indexOf("?");
	return {
		query: q === -1 ? {} : parseParams(beforeHash.slice(q + 1)),
		fragment: hash === -1 ? {} : parseParams(url.slice(hash + 1)),
	};
}

/**
 * Run the native app sign-in: open the provider in the system browser with a
 * PKCE challenge, then trade the single-use code the server returns for a
 * session. The PKCE verifier never leaves the device.
 */
export async function runSocialSignIn(
	base: string,
	provider: string,
	config: SocialSignInConfig,
): Promise<ActionResult<TheAuthSession>> {
	try {
		const randomBytes = config.randomBytes ?? defaultRandomBytes;
		const sha256 = config.sha256 ?? defaultSha256;
		const verifier = base64url(await randomBytes(48));
		const challenge = base64url(await sha256(verifier));

		const params = [
			`mobile_redirect=${encodeURIComponent(config.redirectUri)}`,
			`code_challenge=${challenge}`,
			"code_challenge_method=S256",
		].join("&");
		const authorizeUrl = `${base}/auth/oauth/authorize/${encodeURIComponent(provider)}?${params}`;

		const result = await config.openAuthSession(authorizeUrl, config.redirectUri);
		if (result.type !== "success" || !result.url) {
			return { success: false, error: "Sign-in was cancelled" };
		}

		const { query, fragment } = splitReturnUrl(result.url);
		if (query.error) return { success: false, error: query.error };
		if (fragment.gate) {
			return { success: false, error: `Additional verification required (${fragment.gate})` };
		}
		if (!query.code) return { success: false, error: "Sign-in did not return a code" };

		const res = await fetch(`${base}/auth/oauth/mobile/exchange`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ code: query.code, code_verifier: verifier }),
		});
		const json = (await res.json()) as { data?: TheAuthSession; error?: string };
		if (!res.ok || !json.data) {
			return { success: false, error: json.error ?? `Sign-in failed (${res.status})` };
		}
		return { success: true, data: json.data };
	} catch (err) {
		return { success: false, error: err instanceof Error ? err.message : "Network error" };
	}
}
