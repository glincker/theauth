export type VaultAuthStyle = "client_secret_post" | "client_secret_basic";

export type VaultRefreshBehavior = "always" | "opt_in" | "authorize_param" | "scope";

export interface ProviderPreset {
	id: string;
	name: string;
	authorizationUrl: string;
	tokenUrl: string;
	/** How the provider issues refresh tokens. always: every grant. opt_in: only after a provider setting is enabled. authorize_param: needs extra authorize query params. scope: needs the offline_access scope. */
	refresh: VaultRefreshBehavior;
	refreshNote: string;
	/** Extra query params the authorize request needs for a refresh token. */
	authorizeParams: Record<string, string>;
	/** Always empty. Callers choose scopes. */
	defaultScopes: readonly string[];
	exampleScopes: readonly string[];
	authStyle: VaultAuthStyle;
	docsUrl: string;
}

export const providerPresets = {
	github: {
		id: "github",
		name: "GitHub",
		authorizationUrl: "https://github.com/login/oauth/authorize",
		tokenUrl: "https://github.com/login/oauth/access_token",
		refresh: "opt_in",
		refreshNote:
			"OAuth app tokens do not expire unless token expiration is enabled; then access tokens last 8 hours and refresh tokens rotate (6 months idle).",
		authorizeParams: {},
		defaultScopes: [],
		exampleScopes: ["repo", "read:user", "gist"],
		authStyle: "client_secret_post",
		docsUrl:
			"https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
	},
	google: {
		id: "google",
		name: "Google",
		authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
		tokenUrl: "https://oauth2.googleapis.com/token",
		refresh: "authorize_param",
		refreshNote:
			"Refresh token is returned only with access_type=offline, usually on the first consent; add prompt=consent to get a new one.",
		authorizeParams: { access_type: "offline", prompt: "consent" },
		defaultScopes: [],
		exampleScopes: [
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/calendar.readonly",
			"https://www.googleapis.com/auth/drive.file",
		],
		authStyle: "client_secret_post",
		docsUrl: "https://developers.google.com/identity/protocols/oauth2/web-server",
	},
	slack: {
		id: "slack",
		name: "Slack",
		authorizationUrl: "https://slack.com/oauth/v2/authorize",
		tokenUrl: "https://slack.com/api/oauth.v2.access",
		refresh: "opt_in",
		refreshNote:
			"Tokens do not expire unless token rotation is enabled for the app (cannot be turned off); then access tokens last 12 hours and refresh tokens are single use.",
		authorizeParams: {},
		defaultScopes: [],
		exampleScopes: ["channels:read", "chat:write", "channels:history"],
		authStyle: "client_secret_post",
		docsUrl: "https://docs.slack.dev/authentication/using-token-rotation",
	},
	linear: {
		id: "linear",
		name: "Linear",
		authorizationUrl: "https://linear.app/oauth/authorize",
		tokenUrl: "https://api.linear.app/oauth/token",
		refresh: "always",
		refreshNote:
			"Access tokens last 24 hours; each refresh returns a new refresh token (30 minute replay grace).",
		authorizeParams: {},
		defaultScopes: [],
		exampleScopes: ["read", "issues:create", "comments:create"],
		authStyle: "client_secret_post",
		docsUrl: "https://linear.app/developers/oauth-2-0-authentication",
	},
	microsoft: {
		id: "microsoft",
		name: "Microsoft (Entra v2, common)",
		authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		refresh: "scope",
		refreshNote: "Refresh token is returned only when the offline_access scope is requested.",
		authorizeParams: {},
		defaultScopes: [],
		exampleScopes: ["offline_access", "https://graph.microsoft.com/mail.read", "openid"],
		authStyle: "client_secret_post",
		docsUrl: "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow",
	},
	discord: {
		id: "discord",
		name: "Discord",
		authorizationUrl: "https://discord.com/oauth2/authorize",
		tokenUrl: "https://discord.com/api/oauth2/token",
		refresh: "always",
		refreshNote:
			"Authorization code grant returns a refresh token; the implicit and client credentials grants do not.",
		authorizeParams: {},
		defaultScopes: [],
		exampleScopes: ["identify", "email", "guilds"],
		authStyle: "client_secret_basic",
		docsUrl: "https://docs.discord.com/developers/topics/oauth2",
	},
} as const satisfies Record<string, ProviderPreset>;

export type ProviderPresetId = keyof typeof providerPresets;

export interface PresetCredentials {
	clientId: string;
	clientSecret: string;
}

export interface ResolvedPreset extends PresetCredentials {
	tokenUrl: string;
	authorizationUrl: string;
	authStyle: VaultAuthStyle;
}

/** Pure lookup, no network. Throws on an unknown id or a non https token URL. */
export function resolveProviderPreset(id: string, creds: PresetCredentials): ResolvedPreset {
	const preset = (providerPresets as Record<string, ProviderPreset>)[id];
	if (!preset) throw new Error(`Unknown token vault provider preset: ${id}`);
	if (!preset.tokenUrl.startsWith("https://")) throw new Error("Token URL must be https");
	return {
		tokenUrl: preset.tokenUrl,
		authorizationUrl: preset.authorizationUrl,
		authStyle: preset.authStyle,
		clientId: creds.clientId,
		clientSecret: creds.clientSecret,
	};
}
