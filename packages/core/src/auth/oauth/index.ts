/**
 * OAuth 2.0 / OIDC provider support for TheAuth.
 *
 * @example
 * ```typescript
 * import { createOAuthModule, createGoogleProvider, createGithubProvider, createDiscordProvider } from 'theauth/auth/oauth';
 *
 * const oauth = createOAuthModule(db, {
 *   providers: {
 *     google: createGoogleProvider({
 *       clientId: process.env.GOOGLE_CLIENT_ID,
 *       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 *     }),
 *     github: createGithubProvider({
 *       clientId: process.env.GITHUB_CLIENT_ID,
 *       clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *     }),
 *   },
 * });
 *
 * // Initiate authorization
 * const { url } = await oauth.getAuthorizationUrl('google', 'https://app.example.com/callback');
 *
 * // Handle callback
 * const { account, userInfo, isNewAccount } = await oauth.handleCallback(
 *   'google', code, state, 'https://app.example.com/callback',
 * );
 * ```
 */

// Module factory
export { createOAuthModule } from "./module.js";
// PKCE utilities (useful for testing or custom providers)
export { deriveCodeChallenge, generateCodeVerifier } from "./pkce.js";
export type { OAuthPluginConfig } from "./plugin.js";
// Plugin
export { oauth } from "./plugin.js";
// Built-in providers
export { createAppleProvider } from "./providers/apple.js";
export { createDiscordProvider } from "./providers/discord.js";
export { createGithubProvider } from "./providers/github.js";
export { createGitlabProvider } from "./providers/gitlab.js";
export { createGoogleProvider } from "./providers/google.js";
export { createLinkedInProvider } from "./providers/linkedin.js";
export { createMicrosoftProvider } from "./providers/microsoft.js";
export { createNotionProvider } from "./providers/notion.js";
export { createRedditProvider } from "./providers/reddit.js";
export { createSlackProvider } from "./providers/slack.js";
export { createTwitchProvider } from "./providers/twitch.js";
export { createTwitterProvider } from "./providers/twitter.js";

// Schema tables (for use in migrations or direct DB queries)
export { oauthAccounts, oauthStates } from "./schema.js";

// Types
export type {
	OAuthAccount,
	OAuthCallbackResult,
	OAuthModule,
	OAuthModuleConfig,
	OAuthProvider,
	OAuthProviderConfig,
	OAuthTokens,
	OAuthUserInfo,
} from "./types.js";
