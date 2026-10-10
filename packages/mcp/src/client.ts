import type { Config } from "./config.js";

export interface ApiError {
	code: string;
	message: string;
	/** HTTP status, or 0 when the request never completed. */
	status: number;
}

export type ApiResult<T = unknown> =
	| { ok: true; status: number; data: T }
	| { ok: false; error: ApiError };

export interface RequestOptions {
	query?: Record<string, string | number | undefined>;
	body?: unknown;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * theAuth answers errors in two shapes: `{ error: { code, message } }` from the
 * management routes and `{ error, error_description }` from plugins and OAuth
 * endpoints. Normalise both.
 */
export function parseError(status: number, body: unknown): ApiError {
	if (isRecord(body)) {
		const err = body.error;
		if (isRecord(err)) {
			return {
				code: typeof err.code === "string" ? err.code : `HTTP_${status}`,
				message: typeof err.message === "string" ? err.message : `HTTP ${status}`,
				status,
			};
		}
		if (typeof err === "string") {
			const desc = body.error_description;
			return { code: err, message: typeof desc === "string" ? desc : err, status };
		}
	}
	return { code: `HTTP_${status}`, message: `Request failed with HTTP ${status}`, status };
}

export class ApiClient {
	constructor(
		private readonly config: Config,
		private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
	) {}

	get baseUrl(): string {
		return this.config.apiUrl;
	}

	async request<T = unknown>(
		method: "GET" | "POST",
		path: string,
		options: RequestOptions = {},
	): Promise<ApiResult<T>> {
		const url = new URL(`${this.config.apiUrl}${path}`);
		for (const [k, v] of Object.entries(options.query ?? {})) {
			if (v !== undefined) url.searchParams.set(k, String(v));
		}
		const headers: Record<string, string> = {
			Accept: "application/json",
			Authorization: `Bearer ${this.config.apiKey}`,
		};
		const init: RequestInit = {
			method,
			headers,
			signal: AbortSignal.timeout(this.config.timeoutMs),
		};
		if (options.body !== undefined) {
			headers["Content-Type"] = "application/json";
			init.body = JSON.stringify(options.body);
		}

		let res: Response;
		try {
			res = await this.fetchImpl(url.toString(), init);
		} catch (error) {
			const timedOut = error instanceof Error && error.name === "TimeoutError";
			return {
				ok: false,
				error: {
					code: timedOut ? "TIMEOUT" : "NETWORK_ERROR",
					message: timedOut
						? `Request timed out after ${this.config.timeoutMs} ms`
						: `Could not reach ${this.config.apiUrl}`,
					status: 0,
				},
			};
		}

		let body: unknown;
		try {
			body = await res.json();
		} catch {
			body = undefined;
		}
		if (!res.ok) return { ok: false, error: parseError(res.status, body) };
		const data = isRecord(body) && "data" in body ? body.data : body;
		return { ok: true, status: res.status, data: data as T };
	}
}
