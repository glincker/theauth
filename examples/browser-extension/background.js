// Copy packages/extension/dist/index.js to vendor/theauth-extension.js first
// (run `pnpm --filter @glinr/theauth-extension build`). No bundler is needed
// because the package is a single ES module with no dependencies.
import { createExtensionAuth, exposeAuthToBackground } from "./vendor/theauth-extension.js";

// Replace these with your authorization server and a registered public client.
// Register the value of chrome.identity.getRedirectURL() as its redirect URI.
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
