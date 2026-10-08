import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** One saved login for a TheAuth server. */
export interface CachedCredential {
	accessToken: string;
	tokenType: string;
	/** Unix ms, when the server told us the token lifetime. */
	expiresAt?: number;
	userId?: string;
	savedAt: number;
}

export interface TokenCacheOptions {
	/** Override the file path (tests, custom setups). */
	path?: string;
	env?: NodeJS.ProcessEnv;
	platform?: NodeJS.Platform;
	home?: string;
}

interface CacheFile {
	version: 1;
	servers: Record<string, CachedCredential>;
}

/**
 * Where credentials live:
 * - `THEAUTH_CREDENTIALS_FILE` if set
 * - Windows: `%APPDATA%\theauth\credentials.json`
 * - elsewhere: `$XDG_CONFIG_HOME/theauth/credentials.json`, else `~/.config/theauth/credentials.json`
 */
export function credentialsPath(opts: TokenCacheOptions = {}): string {
	if (opts.path) return opts.path;
	const env = opts.env ?? process.env;
	if (env.THEAUTH_CREDENTIALS_FILE) return env.THEAUTH_CREDENTIALS_FILE;
	const platform = opts.platform ?? process.platform;
	const home = opts.home ?? homedir();
	if (platform === "win32") {
		return join(env.APPDATA ?? join(home, "AppData", "Roaming"), "theauth", "credentials.json");
	}
	return join(env.XDG_CONFIG_HOME || join(home, ".config"), "theauth", "credentials.json");
}

/** Normalise so `https://x.com/` and `https://x.com` share one entry. */
export function serverKey(serverUrl: string): string {
	return serverUrl.trim().replace(/\/+$/, "");
}

async function readFileSafe(path: string): Promise<CacheFile> {
	try {
		const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
		if (parsed && typeof parsed === "object" && (parsed as CacheFile).version === 1) {
			return parsed as CacheFile;
		}
	} catch {
		// missing or corrupt: start empty
	}
	return { version: 1, servers: {} };
}

async function writeCache(path: string, data: CacheFile): Promise<void> {
	const dir = dirname(path);
	await mkdir(dir, { recursive: true, mode: 0o700 });
	const tmp = `${path}.${process.pid}.tmp`;
	// 0600 from creation, so the token is never readable by others, even briefly.
	await writeFile(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
	await chmod(tmp, 0o600);
	await rename(tmp, path);
}

export async function saveCredential(
	serverUrl: string,
	credential: CachedCredential,
	opts: TokenCacheOptions = {},
): Promise<string> {
	const path = credentialsPath(opts);
	const data = await readFileSafe(path);
	data.servers[serverKey(serverUrl)] = credential;
	await writeCache(path, data);
	return path;
}

/** Returns null when absent or expired. */
export async function loadCredential(
	serverUrl: string,
	opts: TokenCacheOptions = {},
): Promise<CachedCredential | null> {
	const data = await readFileSafe(credentialsPath(opts));
	const cred = data.servers[serverKey(serverUrl)];
	if (!cred) return null;
	if (cred.expiresAt !== undefined && cred.expiresAt <= Date.now()) return null;
	return cred;
}

/** Remove one server's credential. Returns true if something was removed. */
export async function clearCredential(
	serverUrl: string,
	opts: TokenCacheOptions = {},
): Promise<boolean> {
	const path = credentialsPath(opts);
	const data = await readFileSafe(path);
	const key = serverKey(serverUrl);
	if (!data.servers[key]) return false;
	const remaining = Object.fromEntries(Object.entries(data.servers).filter(([k]) => k !== key));
	if (Object.keys(remaining).length === 0) await rm(path, { force: true });
	else await writeCache(path, { version: 1, servers: remaining });
	return true;
}

/** Servers with a saved credential, used as the default when `--server` is omitted. */
export async function listServers(opts: TokenCacheOptions = {}): Promise<string[]> {
	return Object.keys((await readFileSafe(credentialsPath(opts))).servers);
}
