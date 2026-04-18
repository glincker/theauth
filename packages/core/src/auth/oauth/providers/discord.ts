/**
 * Discord OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://discord.com/api/oauth2/authorize
 * - Token:         https://discord.com/api/oauth2/token
 * - UserInfo:      https://discord.com/api/users/@me
 *
 * Notes:
 * - PKCE S256 is supported as of the Discord OAuth 2.0 implementation.
 * - The `identify` scope grants access to the user object (ID, username,
 *   avatar). The `email` scope is required separately to receive the email.
 * - Avatar URLs are constructed from the user ID and avatar hash. When the
 *   user has no custom avatar, `avatar` is null and Discord serves a default
 *   based on the discriminator (or username for the new username system).
 * - Discord user IDs are Snowflakes (64-bit integers serialized as strings).
 *
 * Docs: https://discord.com/developers/docs/topics/oauth2
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://discord.com/api/oauth2/authorize";
const TOKEN_URL = "https://discord.com/api/oauth2/token";
const USER_INFO_URL = "https://discord.com/api/users/@me";
const CDN_BASE = "https://cdn.discordapp.com";

export const DEFAULT_DISCORD_SCOPES = ["identify", "email"];
const DEFAULT_SCOPES = DEFAULT_DISCORD_SCOPES;

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface DiscordTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface DiscordUserResponse {
	id: string;
	username: string;
	discriminator?: string;
	global_name?: string | null;
	email?: string | null;
	verified?: boolean;
	avatar?: string | null;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Discord OAuth provider instance.
 *
 * @example
 * ```typescript
 * const discord = createDiscordProvider({
 *   clientId: process.env.DISCORD_CLIENT_ID,
 *   clientSecret: process.env.DISCORD_CLIENT_SECRET,
 * });
 * ```
 */
export function createDiscordProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SCOPES, config.scopes);

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		const codeChallenge = await deriveCodeChallenge(codeVerifier);
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			response_type: "code",
			scope: scopes.join(" "),
			state,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
		});

		return `${AUTHORIZATION_URL}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const body = new URLSearchParams({
			grant_type: "authorization_code",
			client_id: config.clientId,
			client_secret: config.clientSecret,
			code,
			code_verifier: codeVerifier,
			redirect_uri: effectiveRedirectUri,
		});

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Discord token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as DiscordTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		const response = await fetch(USER_INFO_URL, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Discord users/@me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as DiscordUserResponse;

		if (!data.id) {
			throw new Error("Discord user response missing required field: id");
		}

		if (!data.email) {
			throw new Error("Discord user response has no email. Ensure the `email` scope is granted.");
		}

		const avatar = buildAvatarUrl(data.id, data.avatar);

		// Prefer the new `global_name` (pomelo username system); fall back to
		// the legacy `username#discriminator` display.
		const name = data.global_name ?? buildLegacyName(data.username, data.discriminator);

		return {
			id: data.id,
			email: data.email,
			name,
			avatar,
			raw,
		};
	}

	return {
		id: "discord",
		name: "Discord",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userInfoUrl: USER_INFO_URL,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		getUserInfo,
	};
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as DiscordUserResponse;

	if (!data.id) {
		throw new Error("Discord user response missing required field: id");
	}

	if (!data.email) {
		throw new Error("Discord user response has no email. Ensure the `email` scope is granted.");
	}

	const avatar = buildAvatarUrl(data.id, data.avatar);
	const name = data.global_name ?? buildLegacyName(data.username, data.discriminator);

	return {
		id: data.id,
		email: data.email,
		name,
		avatar,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildAvatarUrl(userId: string, avatarHash: string | null | undefined): string | undefined {
	if (!avatarHash) return undefined;
	const ext = avatarHash.startsWith("a_") ? "gif" : "png";
	return `${CDN_BASE}/avatars/${userId}/${avatarHash}.${ext}`;
}

function buildLegacyName(username: string, discriminator?: string): string {
	if (discriminator && discriminator !== "0") {
		return `${username}#${discriminator}`;
	}
	return username;
}

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	const merged = new Set([...defaults, ...extras]);
	return [...merged];
}
