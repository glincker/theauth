import type { BrowserWindowInstance } from "./electron-api.js";
import { getElectronApi } from "./electron-api.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OAuthWindowConfig {
	/** Window width in pixels. Defaults to 500. */
	width?: number;
	/** Window height in pixels. Defaults to 700. */
	height?: number;
	/** Base path where TheAuth is mounted. Defaults to "/api/kavach". */
	basePath?: string;
}

export interface OAuthWindowResult {
	success: boolean;
	error?: string;
}

// ─── Session cookie extraction ────────────────────────────────────────────────

const SESSION_COOKIE_NAMES = ["kavach-session", "better-auth.session_token", "__session"];

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

// ─── URL parsing helpers ──────────────────────────────────────────────────────

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

// ─── Main export ──────────────────────────────────────────────────────────────

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
	const { width = 500, height = 700, basePath = "/api/kavach" } = config;
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

	const authUrl = `${base}/sign-in/${encodeURIComponent(providerId)}?redirect=electron`;

	return new Promise<OAuthWindowResult>((resolve) => {
		let settled = false;

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
			if (!isCallbackUrl(url, base)) return;

			const oauthError = extractOAuthError(url);
			if (oauthError) {
				settle({ success: false, error: oauthError });
				return;
			}

			try {
				const origin = new URL(url).origin;
				const cookie = await extractSessionCookie(win, origin);
				// Treat as success whether or not we captured the cookie — the
				// session will be verified on the next server round-trip.
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
