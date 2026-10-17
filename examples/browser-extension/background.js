// Copy packages/extension/dist/index.js to vendor/theauth-extension.js first (pnpm --filter @glinr/theauth-extension build).
// Single ES module with no dependencies, so no bundler is needed.
import { createExtensionAuth, exposeAuthToBackground } from "./vendor/theauth-extension.js";

// Use your authorization server and a registered public client. Register chrome.identity.getRedirectURL() as its redirect URI.
const auth = createExtensionAuth({
	issuer: "https://auth.example.com",
	clientId: "REPLACE_WITH_CLIENT_ID",
	scopes: ["openid", "offline_access"],
	encryptRefreshToken: true,
});

// Top level, so the listener exists every time the worker wakes up.
exposeAuthToBackground(auth);

auth.onChange((session) => {
	void chrome.action.setBadgeText({ text: session ? "on" : "" });
});
