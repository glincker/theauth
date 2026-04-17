/**
 * OAuth / OIDC provider exports.
 *
 * First-class named providers (createXProvider) plus the generic OIDC factory
 * and legacy preset helpers for services that do not yet have a dedicated file.
 */

// Apple
export { createAppleProvider } from "./apple.js";

// Atlassian
export {
	createAtlassianProvider,
	DEFAULT_ATLASSIAN_SCOPES,
	normalizeProfile as normalizeAtlassianProfile,
} from "./atlassian.js";

// Discord
export {
	createDiscordProvider,
	DEFAULT_DISCORD_SCOPES,
	normalizeProfile as normalizeDiscordProfile,
} from "./discord.js";

// Dropbox
export {
	createDropboxProvider,
	DEFAULT_DROPBOX_SCOPES,
	normalizeProfile as normalizeDropboxProfile,
} from "./dropbox.js";

// Figma
export {
	createFigmaProvider,
	DEFAULT_FIGMA_SCOPES,
	normalizeProfile as normalizeFigmaProfile,
} from "./figma.js";

// Generic OIDC factory
export type { GenericOIDCConfig } from "./generic.js";
export { genericOIDC } from "./generic.js";

// GitHub
export { createGithubProvider } from "./github.js";

// GitLab
export { createGitlabProvider } from "./gitlab.js";

// Google
export { createGoogleProvider } from "./google.js";

// LinkedIn
export { createLinkedInProvider } from "./linkedin.js";

// Microsoft
export { createMicrosoftProvider } from "./microsoft.js";

// Notion
export {
	createNotionProvider,
	DEFAULT_NOTION_SCOPES,
	normalizeProfile as normalizeNotionProfile,
} from "./notion.js";
// Legacy preset providers — kept for backwards compatibility.
// These use the genericOIDC factory directly and have a different signature
// (clientId, clientSecret) vs. the first-class (OAuthProviderConfig) pattern.
export {
	atlassianProvider,
	auth0Provider,
	bitbucketProvider,
	cognitoProvider,
	coinbaseProvider,
	dropboxProvider,
	facebookProvider,
	figmaProvider,
	huggingfaceProvider,
	kakaoProvider,
	kickProvider,
	linearProvider,
	lineProvider,
	naverProvider,
	notionProvider,
	oktaProvider,
	paypalProvider,
	polarProvider,
	railwayProvider,
	redditProvider,
	robloxProvider,
	salesforceProvider,
	spotifyProvider,
	tiktokProvider,
	twitchProvider,
	vercelProvider,
	vkProvider,
	wechatProvider,
	yahooProvider,
	zoomProvider,
} from "./presets.js";
// Reddit
export {
	createRedditProvider,
	DEFAULT_REDDIT_SCOPES,
	normalizeProfile as normalizeRedditProfile,
} from "./reddit.js";
// Slack
export {
	createSlackProvider,
	DEFAULT_SLACK_SCOPES,
	normalizeProfile as normalizeSlackProfile,
} from "./slack.js";
// Spotify
export {
	createSpotifyProvider,
	DEFAULT_SPOTIFY_SCOPES,
	normalizeProfile as normalizeSpotifyProfile,
} from "./spotify.js";
// Twitch
export {
	createTwitchProvider,
	DEFAULT_TWITCH_SCOPES,
	normalizeProfile as normalizeTwitchProfile,
} from "./twitch.js";
// Twitter / X
export { createTwitterProvider } from "./twitter.js";
// Zoom
export {
	createZoomProvider,
	DEFAULT_ZOOM_SCOPES,
	normalizeProfile as normalizeZoomProfile,
} from "./zoom.js";
