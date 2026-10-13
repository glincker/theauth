import { createHmac, timingSafeEqual } from "node:crypto";
import type { Stats } from "node:fs";
import { createReadStream, existsSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { extname, join, resolve, sep } from "node:path";
import { env, stdout } from "node:process";

// Options

export interface DashboardServerOptions {
	port: number;
	apiUrl: string;
}

// MIME Types

const MIME_TYPES: Record<string, string> = {
	".html": "text/html; charset=utf-8",
	".js": "application/javascript; charset=utf-8",
	".mjs": "application/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".jpg": "image/jpeg",
	".jpeg": "image/jpeg",
	".ico": "image/x-icon",
	".woff": "font/woff",
	".woff2": "font/woff2",
	".ttf": "font/ttf",
	".map": "application/json; charset=utf-8",
};

function getMimeType(filePath: string): string {
	const ext = extname(filePath).toLowerCase();
	return MIME_TYPES[ext] ?? "application/octet-stream";
}

// Dist Dir Resolution

function resolveDashboardDistDir(): string {
	// Try resolving from the @glinr/theauth-dashboard package first
	try {
		const require = createRequire(import.meta.url);
		const pkgPath = require.resolve("@glinr/theauth-dashboard/package.json");
		const pkgDir = resolve(pkgPath, "..");
		const distDir = join(pkgDir, "dist", "app");
		if (existsSync(distDir)) {
			return distDir;
		}
	} catch {
		// Package not found on node_modules path — try relative paths
	}

	// Fallback: look relative to this file (monorepo layout)
	const candidates = [
		// Running from source: packages/cli/src -> packages/dashboard/dist/app
		join(new URL(".", import.meta.url).pathname, "..", "..", "..", "dashboard", "dist", "app"),
		// Running from dist:  packages/cli/dist -> packages/dashboard/dist/app
		join(new URL(".", import.meta.url).pathname, "..", "..", "..", "dashboard", "dist", "app"),
	];

	for (const candidate of candidates) {
		if (existsSync(candidate)) {
			return candidate;
		}
	}

	throw new Error(
		"Cannot find @glinr/theauth-dashboard dist directory.\n" +
			"Make sure the dashboard package is built first:\n\n" +
			"  cd packages/dashboard && npm run build\n",
	);
}

// HTML Injection

async function readIndexHtml(distDir: string, apiUrl: string): Promise<string> {
	const indexPath = join(distDir, "index.html");
	const html = await readFile(indexPath, "utf-8");

	// Inject the API URL as a global before any other scripts load
	const injection = `<script>window.__THEAUTH_API_URL__ = ${JSON.stringify(apiUrl)};</script>`;

	// Prefer injecting right before </head>; fall back to prepend
	if (html.includes("</head>")) {
		return html.replace("</head>", `${injection}</head>`);
	}
	return injection + html;
}

// Static File Handler

function send404(res: ServerResponse): void {
	res.writeHead(404, { "Content-Type": "text/plain" });
	res.end("Not Found");
}

/**
 * Decode a request path. Returns null for a malformed escape (which makes
 * decodeURIComponent throw) or an embedded NUL byte, so the caller can answer
 * 400 instead of crashing the process.
 */
export function decodePathname(raw: string): string | null {
	try {
		const decoded = decodeURIComponent(raw);
		return decoded.includes("\0") ? null : decoded;
	} catch {
		return null;
	}
}

/** Compare two secrets without leaking their common prefix through timing. */
export function secretsMatch(provided: string, expected: string): boolean {
	const a = Buffer.from(provided);
	const b = Buffer.from(expected);
	return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Serve a regular file from inside `root`. Answers 404 and returns true when
 * the request escapes the root, and returns false when there is no such file
 * so the caller can fall back to index.html.
 */
export function serveStatic(root: string, pathname: string, res: ServerResponse): boolean {
	const rootPrefix = resolve(root) + sep;
	const target = resolve(rootPrefix, `.${pathname}`);
	if (!target.startsWith(rootPrefix)) {
		send404(res);
		return true;
	}
	let stat: Stats;
	try {
		stat = statSync(target);
	} catch {
		return false;
	}
	if (!stat.isFile()) return false;
	res.writeHead(200, {
		"Content-Type": getMimeType(target),
		"Content-Length": stat.size,
		"Cache-Control": "public, max-age=31536000, immutable",
	});
	createReadStream(target).pipe(res);
	return true;
}

// Auth

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): void {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(payload),
	});
	res.end(payload);
}

function resolveDashboardSecret(): string | null {
	return env.THEAUTH_DASHBOARD_SECRET ?? null;
}

export const DASHBOARD_COOKIE = "theauth_dashboard";
const SESSION_SECONDS = 8 * 60 * 60;

function cookieKey(secret: string): Uint8Array {
	return createHmac("sha256", "theauth-dashboard-cookie").update(secret).digest();
}

/** Signed `expiry.signature` value. The signing key is derived from the secret. */
export function signDashboardCookie(secret: string, now = Date.now()): string {
	const expires = String(Math.floor(now / 1000) + SESSION_SECONDS);
	const mac = createHmac("sha256", cookieKey(secret)).update(expires).digest("base64url");
	return `${expires}.${mac}`;
}

export function verifyDashboardCookie(secret: string, value: string, now = Date.now()): boolean {
	const dot = value.indexOf(".");
	if (dot < 1) return false;
	const expires = value.slice(0, dot);
	if (!/^\d{1,12}$/.test(expires) || Number(expires) * 1000 <= now) return false;
	const expected = createHmac("sha256", cookieKey(secret)).update(expires).digest("base64url");
	return secretsMatch(value.slice(dot + 1), expected);
}

function readCookie(req: IncomingMessage, name: string): string {
	for (const part of (req.headers.cookie ?? "").split(";")) {
		const eq = part.indexOf("=");
		if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
	}
	return "";
}

function isHttps(req: IncomingMessage): boolean {
	const forwarded = req.headers["x-forwarded-proto"];
	const proto = Array.isArray(forwarded) ? forwarded[0] : forwarded;
	return proto?.split(",")[0]?.trim() === "https" || "encrypted" in req.socket;
}

function sessionCookie(value: string, maxAge: number, secure: boolean): string {
	return [
		`${DASHBOARD_COOKIE}=${value}`,
		"HttpOnly",
		"SameSite=Strict",
		"Path=/",
		`Max-Age=${maxAge}`,
		...(secure ? ["Secure"] : []),
	].join("; ");
}

/**
 * `/api/dashboard/auth`
 * - POST with `Authorization: Bearer <secret>` signs in and sets an HttpOnly,
 *   SameSite=Strict cookie, so the secret never reaches page script or storage.
 * - GET reports whether the cookie (or a bearer secret) is valid.
 * - DELETE signs out.
 */
export function handleAuthRequest(
	req: IncomingMessage,
	res: ServerResponse,
	secret: string | null,
): boolean {
	const rawUrl = req.url ?? "/";
	const pathname = rawUrl.split("?")[0] ?? "/";

	if (pathname !== "/api/dashboard/auth") return false;

	// No secret configured: open dev mode
	if (secret === null) {
		sendJson(res, 200, { ok: true, mode: "dev" });
		return true;
	}

	const secure = isHttps(req);
	if (req.method === "DELETE") {
		res.setHeader("Set-Cookie", sessionCookie("", 0, secure));
		sendJson(res, 200, { ok: true });
		return true;
	}

	const authHeader = req.headers.authorization ?? "";
	const provided = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
	const bearerOk = provided !== "" && secretsMatch(provided, secret);

	if (req.method === "POST") {
		if (!bearerOk) {
			sendJson(res, 401, { code: "UNAUTHORIZED", message: "Invalid dashboard secret." });
			return true;
		}
		res.setHeader(
			"Set-Cookie",
			sessionCookie(signDashboardCookie(secret), SESSION_SECONDS, secure),
		);
		sendJson(res, 200, { ok: true });
		return true;
	}

	const cookieOk = verifyDashboardCookie(secret, readCookie(req, DASHBOARD_COOKIE));
	if (bearerOk || cookieOk) {
		sendJson(res, 200, { ok: true });
	} else {
		sendJson(res, 401, { code: "UNAUTHORIZED", message: "Invalid dashboard secret." });
	}
	return true;
}

// Server

export async function startDashboardServer(options: DashboardServerOptions): Promise<void> {
	const { port, apiUrl } = options;

	const dashboardSecret = resolveDashboardSecret();

	if (dashboardSecret === null) {
		stdout.write("  [warn] THEAUTH_DASHBOARD_SECRET is not set — dashboard auth is disabled.\n");
	}

	const distDir = resolveDashboardDistDir();

	// Pre-read and patch index.html once at startup
	const indexHtml = await readIndexHtml(distDir, apiUrl);
	const indexHtmlBuffer = Buffer.from(indexHtml, "utf-8");

	function handleRequest(req: IncomingMessage, res: ServerResponse): void {
		const rawUrl = req.url ?? "/";
		// Strip query string and decode
		const pathname = decodePathname(rawUrl.split("?")[0] ?? "/");
		if (pathname === null) {
			sendJson(res, 400, { code: "BAD_REQUEST", message: "Malformed request path." });
			return;
		}

		// Auth endpoint — handled before static files
		if (handleAuthRequest(req, res, dashboardSecret)) return;

		// SPA: serve index.html for navigation routes (no file extension)
		const isSpaRoute = extname(pathname) === "";
		if (isSpaRoute) {
			res.writeHead(200, {
				"Content-Type": "text/html; charset=utf-8",
				"Content-Length": indexHtmlBuffer.byteLength,
				"Cache-Control": "no-cache",
			});
			res.end(indexHtmlBuffer);
			return;
		}

		// Static asset, falling back to index.html for unknown paths (SPA catch-all)
		if (serveStatic(distDir, pathname, res)) return;
		res.writeHead(200, {
			"Content-Type": "text/html; charset=utf-8",
			"Content-Length": indexHtmlBuffer.byteLength,
			"Cache-Control": "no-cache",
		});
		res.end(indexHtmlBuffer);
	}

	const server = createServer(handleRequest);

	await new Promise<void>((resolvePromise, reject) => {
		server.on("error", reject);
		server.listen(port, () => resolvePromise());
	});

	stdout.write("\n");
	stdout.write("  TheAuth Dashboard\n");
	stdout.write("  ==================\n\n");
	stdout.write(`  Local:   http://localhost:${port}\n`);
	stdout.write(`  API:     ${apiUrl}\n\n`);
	stdout.write("  Press Ctrl+C to stop.\n\n");
}
