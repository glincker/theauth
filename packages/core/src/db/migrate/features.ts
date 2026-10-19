import type { TheAuthConfig } from "../../types.js";

/** Feature flags that decide which tables a config needs. */
export interface EnabledFeatures {
	core: true; // always
	session: boolean;
	agent: boolean;
	audit: boolean;
	oauth: boolean;
	tenant: boolean;
	mcp: boolean;
	org: boolean;
	rateLimit: boolean;
	budget: boolean;
	magicLink: boolean;
	emailOtp: boolean;
	totp: boolean;
	passkey: boolean;
	sso: boolean;
	apiKey: boolean;
	username: boolean;
	phone: boolean;
	device: boolean;
	oneTimeToken: boolean;
	loginHistory: boolean;
	oidcProvider: boolean;
	jwt: boolean;
	rebac: boolean;
	federation: boolean;
	secondaryStorage: boolean;
	tokenVault: boolean;
	sharedSignals: boolean;
}

export const ALL_FEATURES_ENABLED: EnabledFeatures = {
	core: true,
	session: true,
	agent: true,
	audit: true,
	oauth: true,
	tenant: true,
	mcp: true,
	org: true,
	rateLimit: true,
	budget: true,
	magicLink: true,
	emailOtp: true,
	totp: true,
	passkey: true,
	sso: true,
	apiKey: true,
	username: true,
	phone: true,
	device: true,
	oneTimeToken: true,
	loginHistory: true,
	oidcProvider: true,
	jwt: true,
	rebac: true,
	federation: true,
	secondaryStorage: true,
	tokenVault: true,
	sharedSignals: true,
};

export function resolveEnabledFeatures(config?: TheAuthConfig): EnabledFeatures {
	if (!config) {
		// Backward compat: no config = create everything
		return ALL_FEATURES_ENABLED;
	}

	const hasAgents = !!config.agents || !!config.did; // DID module always requires agent tables
	const hasSession = !!config.auth?.session;
	const hasOAuth = config.plugins?.some((p) => p.id === "theauth-oauth") ?? false;
	const hasOidc = config.plugins?.some((p) => p.id === "theauth-oidc-provider") ?? false;

	// Plugin form (`plugins: [magicLink(...)]`) must create the same tables as
	// the config-key form (`magicLink: {...}`), so look at plugin ids too.
	const hasPlugin = (id: string): boolean => config.plugins?.some((p) => p.id === id) ?? false;
	const hasMagicLink = !!config.magicLink || hasPlugin("theauth-magic-link");
	const hasEmailOtp = !!config.emailOtp || hasPlugin("theauth-email-otp");

	return {
		core: true,
		session: hasSession,
		agent: hasAgents,
		audit: hasAgents,
		// MCP stores keep clients, codes and tokens in the oauth tables.
		oauth: hasOAuth || !!config.mcp,
		tenant: hasAgents,
		mcp: !!config.mcp,
		org: !!config.org || hasPlugin("theauth-organization"),
		rateLimit: hasAgents,
		budget: hasAgents,
		magicLink: hasMagicLink,
		emailOtp: hasEmailOtp,
		totp: !!config.totp || hasPlugin("theauth-2fa"),
		passkey: !!config.passkey || hasPlugin("theauth-passkey"),
		sso: !!config.sso,
		apiKey: !!config.apiKeys || hasPlugin("theauth-api-key"),
		username: !!config.username || !!config.emailPassword,
		phone: !!config.phone,
		device: hasSession,
		// OAuth plugins hold the native app sign-in codes here.
		oneTimeToken:
			hasMagicLink ||
			hasEmailOtp ||
			!!config.passwordReset ||
			!!config.emailVerification ||
			hasOAuth,
		loginHistory: hasSession,
		oidcProvider: hasOidc,
		// MCP refresh token families live in the jwt family tables.
		jwt: hasSession || !!config.mcp,
		rebac: hasAgents,
		federation: false, // only when explicitly configured (no config key yet)
		// Tiny table, created always so `secondaryStorage: "database"` just works.
		secondaryStorage: true,
		tokenVault: hasPlugin("theauth-token-vault"),
		sharedSignals: hasPlugin("theauth-shared-signals"),
	};
}

export type FeatureKey = keyof EnabledFeatures;
