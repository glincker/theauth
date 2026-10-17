/**
 * OAuth / OIDC provider exports.
 * First-class named providers (createXProvider) plus the generic OIDC factory and legacy preset helpers for services that do not yet have a dedicated file.
 */

export { createAppleProvider } from "./apple.js";

export {
	createAtlassianProvider,
	DEFAULT_ATLASSIAN_SCOPES,
	normalizeProfile as normalizeAtlassianProfile,
} from "./atlassian.js";

export {
	createDiscordProvider,
	DEFAULT_DISCORD_SCOPES,
	normalizeProfile as normalizeDiscordProfile,
} from "./discord.js";

export {
	createDropboxProvider,
	DEFAULT_DROPBOX_SCOPES,
	normalizeProfile as normalizeDropboxProfile,
} from "./dropbox.js";

export {
	createFigmaProvider,
	DEFAULT_FIGMA_SCOPES,
	normalizeProfile as normalizeFigmaProfile,
} from "./figma.js";

export type { GenericOIDCConfig } from "./generic.js";
export { genericOIDC } from "./generic.js";

export { createGithubProvider } from "./github.js";

export { createGitlabProvider } from "./gitlab.js";

export { createGoogleProvider } from "./google.js";
export { createKakaoProvider, DEFAULT_KAKAO_SCOPES } from "./kakao.js";
export { createKickProvider, DEFAULT_KICK_SCOPES } from "./kick.js";
export { createLinearProvider, DEFAULT_LINEAR_SCOPES } from "./linear.js";
export { createLinkedInProvider } from "./linkedin.js";
export { createMicrosoftProvider } from "./microsoft.js";
// Notion
export {
	createNotionProvider,
	DEFAULT_NOTION_SCOPES,
	normalizeProfile as normalizeNotionProfile,
} from "./notion.js";
export {
	createPaypalProvider,
	DEFAULT_PAYPAL_SCOPES,
	type PaypalProviderConfig,
} from "./paypal.js";
// Legacy preset providers, kept for backwards compatibility.
// These use the genericOIDC factory directly and have a different signature
// (clientId, clientSecret) vs. the first-class (OAuthProviderConfig) pattern.
export {
	atlassianProvider,
	auth0Provider,
	authentikProvider,
	bitbucketProvider,
	boxProvider,
	cognitoProvider,
	coinbaseProvider,
	dropboxProvider,
	facebookProvider,
	figmaProvider,
	giteaProvider,
	huggingfaceProvider,
	kakaoProvider,
	keycloakProvider,
	kickProvider,
	linearProvider,
	lineProvider,
	naverProvider,
	notionProvider,
	oktaProvider,
	oneloginProvider,
	patreonProvider,
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
	wordpressProvider,
	yahooProvider,
	yandexProvider,
	zitadelProvider,
	zoomProvider,
} from "./presets.js";
export {
	createRedditProvider,
	DEFAULT_REDDIT_SCOPES,
	normalizeProfile as normalizeRedditProfile,
} from "./reddit.js";
export {
	createSlackProvider,
	DEFAULT_SLACK_SCOPES,
	normalizeProfile as normalizeSlackProfile,
} from "./slack.js";
export {
	createSpotifyProvider,
	DEFAULT_SPOTIFY_SCOPES,
	normalizeProfile as normalizeSpotifyProfile,
} from "./spotify.js";
export {
	createTwitchProvider,
	DEFAULT_TWITCH_SCOPES,
	normalizeProfile as normalizeTwitchProfile,
} from "./twitch.js";
export { createTwitterProvider } from "./twitter.js";
export { createVercelProvider, DEFAULT_VERCEL_SCOPES } from "./vercel.js";
export {
	createZoomProvider,
	DEFAULT_ZOOM_SCOPES,
	normalizeProfile as normalizeZoomProfile,
} from "./zoom.js";
