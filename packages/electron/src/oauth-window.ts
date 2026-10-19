import type { BrowserWindowInstance } from "./electron-api.js";
import { getElectronApi } from "./electron-api.js";

export interface OAuthWindowConfig {
	width?: number;
	height?: number;
	basePath?: string;
}

export interface OAuthWindowResult {
	success: boolean;
	error?: string;
}

const SESSION_COOKIE_NAMES = ["theauth-session", "better-auth.session_token", "__session"];

async function extractSessionCookie(
	win: BrowserWindowInstance,
	baseUrl: string,
): Promise<string | null> {
	const cookies = await win.webContents.session.cookies.get({ url: baseUrl });
	for (const name of SESSION_COOKIE_NAMES) {
		const cookie = cookies.find((c) => c.name === name);
		if (cookie) return cookie.value;
	}
	return null;
}

/** The core's own callback route, `GET /auth/oauth/callback/:provider`. It sets the session cookie. */
function isServerCallback(url: string, base: string): boolean {
	return url.includes(`${base.replace(/\/$/, "")}/auth/oauth/callback/`);
}

function isCallbackUrl(url: string, base: string): boolean {
	const normalised = base.replace(/\/$/, "");
	return (
		url.includes(`${normalised}/callback`) ||
		url.includes(`${normalised}/oauth/callback`) ||
		url.includes("code=") ||
		url.includes("error=")
	);
}

function extractOAuthError(url: string): string | null {
	try {
		// Use a dummy base so relative paths are accepted
		const parsed = new URL(url, "http://localhost");
		return parsed.searchParams.get("error_description") ?? parsed.searchParams.get("error");
	} catch {
		return null;
	}
}

/**
 * Opens a BrowserWindow to the OAuth authorization URL for a given provider,
 * waits for the callback redirect, extracts the session cookie, then closes
 * the window.
 *
 * Must be called from the Electron main process.
 */
export async function openOAuthWindow(
	providerId: string,
	config: OAuthWindowConfig = {},
): Promise<OAuthWindowResult> {
	const { width = 500, height = 700, basePath = "/api/theauth" } = config;
	const base = basePath.replace(/\/$/, "");

	const { BrowserWindow } = getElectronApi();

	const win = new BrowserWindow({
		width,
		height,
		webPreferences: {
			nodeIntegration: false,
			contextIsolation: true,
			sandbox: true,
		},
		title: "Sign in",
		resizable: false,
		minimizable: false,
		maximizable: false,
		show: false,
	});

	const authUrl = `${base}/auth/oauth/authorize/${encodeURIComponent(providerId)}`;

	return new Promise<OAuthWindowResult>((resolve) => {
		let settled = false;
		// Set once the browser reaches the core callback. The provider's redirect to it
		// carries `code=`, but the server has not set the cookie yet, so we must not stop there.
		let sawServerCallback = false;

		function settle(result: OAuthWindowResult): void {
			if (settled) return;
			settled = true;
			win.destroy();
			resolve(result);
		}

		win.on("closed", () => {
			settle({ success: false, error: "Window closed by user" });
		});

		async function handleNavigate(_event: unknown, url: string): Promise<void> {
			const oauthError = isCallbackUrl(url, base) ? extractOAuthError(url) : null;
			if (oauthError) {
				settle({ success: false, error: oauthError });
				return;
			}
			if (isServerCallback(url, base)) {
				sawServerCallback = true;
				return;
			}
			// After the core callback ran, its redirect back to the app means the cookie is set.
			if (!sawServerCallback && !isCallbackUrl(url, base)) return;

			try {
				const origin = new URL(url).origin;
				const cookie = await extractSessionCookie(win, origin);
				// Success either way. The session is verified on the next server round-trip.
				void cookie;
				settle({ success: true });
			} catch (err) {
				settle({
					success: false,
					error: err instanceof Error ? err.message : "Failed to extract session",
				});
			}
		}

		win.webContents.on("will-redirect", (ev, url) => {
			void handleNavigate(ev, url);
		});
		win.webContents.on("will-navigate", (ev, url) => {
			void handleNavigate(ev, url);
		});

		void win.loadURL(authUrl).then(() => {
			win.show();
		});
	});
}
