export interface HttpResult {
	url: string;
	status: number;
	headers: Headers;
	text: string;
	json: unknown;
}

export type JsonRecord = Record<string, unknown>;

export function asRecord(value: unknown): JsonRecord | null {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as JsonRecord)
		: null;
}

export function asString(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

export function asStringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

export function isLoopback(url: URL): boolean {
	const host = url.hostname;
	return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

/** Single request with a timeout. Redirects are never followed. Throws on network failure. */
export async function request(
	url: string,
	init: RequestInit,
	timeoutMs: number,
): Promise<HttpResult> {
	const response = await fetch(url, {
		...init,
		redirect: "manual",
		signal: AbortSignal.timeout(timeoutMs),
	});
	const text = await response.text();
	let json: unknown = null;
	try {
		json = text.length > 0 ? JSON.parse(text) : null;
	} catch {
		json = null;
	}
	return { url, status: response.status, headers: response.headers, text, json };
}

export function formBody(params: Record<string, string>): RequestInit {
	return {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
		body: new URLSearchParams(params).toString(),
	};
}

export function jsonBody(body: unknown): RequestInit {
	return {
		method: "POST",
		headers: { "Content-Type": "application/json", Accept: "application/json" },
		body: JSON.stringify(body),
	};
}

/** Short body excerpt for evidence, never the whole page. */
export function excerpt(text: string, max = 200): string {
	return text.length > max ? `${text.slice(0, max)}...` : text;
}
