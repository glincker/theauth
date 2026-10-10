/** Environment-driven configuration. The API key is never logged or echoed. */

export class ConfigError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ConfigError";
	}
}

export interface Config {
	/** Base URL of the theAuth HTTP API, without a trailing slash. */
	apiUrl: string;
	/** Bearer credential the deployment's management routes accept. */
	apiKey: string;
	/** Per-request timeout in milliseconds. */
	timeoutMs: number;
}

export const DEFAULT_TIMEOUT_MS = 10_000;

function positiveInt(name: string, raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const n = Number(raw);
	if (!Number.isInteger(n) || n <= 0) {
		throw new ConfigError(`${name} must be a positive integer (milliseconds), got "${raw}"`);
	}
	return n;
}

export function loadConfig(env: NodeJS.ProcessEnv): Config {
	const rawUrl = env.THEAUTH_API_URL?.trim();
	const apiKey = env.THEAUTH_API_KEY?.trim();
	const missing: string[] = [];
	if (!rawUrl) missing.push("THEAUTH_API_URL");
	if (!apiKey) missing.push("THEAUTH_API_KEY");
	if (!rawUrl || !apiKey) {
		throw new ConfigError(`Missing required environment variable(s): ${missing.join(", ")}`);
	}
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		throw new ConfigError("THEAUTH_API_URL is not a valid URL");
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		throw new ConfigError("THEAUTH_API_URL must start with http:// or https://");
	}
	return {
		apiUrl: rawUrl.replace(/\/+$/, ""),
		apiKey,
		timeoutMs: positiveInt("THEAUTH_TIMEOUT_MS", env.THEAUTH_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
	};
}
