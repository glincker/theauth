/**
 * A typed caller for plugin endpoints declared with `defineEndpoint`.
 *
 * Import the route map as a type only, so no server code reaches the bundle:
 *
 * ```ts
 * import type { ApiOf } from "@glinr/theauth";
 * import type { endpoints } from "./server/endpoints";
 * const api = createEndpointClient<ApiOf<typeof endpoints>>({ baseUrl: "/api/theauth" });
 * const out = await api.call("POST /auth/team/invite", { body: { email: "a@b.c" } });
 * ```
 */

export interface RouteShape {
	params?: unknown;
	query?: unknown;
	body?: unknown;
	response?: unknown;
}

type Present<T> = [T] extends [undefined] ? never : T;

type Field<K extends string, T> = [Present<T>] extends [never]
	? { [P in K]?: undefined }
	: Record<never, never> extends Present<T>
		? { [P in K]?: Present<T> }
		: { [P in K]: Present<T> };

/** What a caller passes for a route. Fields the route does not declare are absent. */
export type EndpointCallInput<R extends RouteShape> = Field<"params", R["params"]> &
	Field<"query", R["query"]> &
	Field<"body", R["body"]>;

type HasRequired<T> = Record<never, never> extends T ? false : true;

export type EndpointResult<T> =
	| { ok: true; status: number; data: T }
	| { ok: false; status: number; error: { code: string; message: string; issues?: unknown } };

export interface EndpointClientOptions {
	/** Where the plugin routes are mounted, e.g. `/api/theauth`. */
	baseUrl: string;
	fetch?: typeof fetch;
	/** Extra headers on every call, e.g. `Authorization`. */
	headers?: HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
	/** Send cookies. Default `"include"`. */
	credentials?: RequestCredentials;
}

export interface EndpointClient<Api extends Record<string, RouteShape>> {
	call<K extends keyof Api & string>(
		route: K,
		...args: HasRequired<EndpointCallInput<Api[K]>> extends true
			? [input: EndpointCallInput<Api[K]>]
			: [input?: EndpointCallInput<Api[K]>]
	): Promise<EndpointResult<Api[K]["response"]>>;
}

const ROUTE_RE = /^(GET|POST|PUT|PATCH|DELETE) (\/\S*)$/;

function fillPath(path: string, params: Record<string, unknown> | undefined): string {
	return path.replace(/:([A-Za-z0-9_]+)/g, (_m, name: string) => {
		const value = params?.[name];
		if (value === undefined || value === null) {
			throw new Error(`Missing path parameter "${name}" for ${path}`);
		}
		return encodeURIComponent(String(value));
	});
}

export function createEndpointClient<Api extends Record<string, RouteShape>>(
	options: EndpointClientOptions,
): EndpointClient<Api> {
	let end = options.baseUrl.length;
	while (end > 0 && options.baseUrl.charCodeAt(end - 1) === 47) end--;
	const base = options.baseUrl.slice(0, end);
	const doFetch = options.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));

	return {
		async call(route, ...args) {
			const match = ROUTE_RE.exec(route);
			if (!match) throw new Error(`Invalid route "${route}". Expected "METHOD /path".`);
			const [, method, path] = match as unknown as [string, string, string];
			const input = (args[0] ?? {}) as {
				params?: Record<string, unknown>;
				query?: Record<string, unknown>;
				body?: unknown;
			};

			const search = new URLSearchParams();
			for (const [k, v] of Object.entries(input.query ?? {})) {
				if (v !== undefined && v !== null) search.set(k, String(v));
			}
			const qs = search.toString();
			const target = `${base}${fillPath(path, input.params)}${qs ? `?${qs}` : ""}`;

			const extra =
				typeof options.headers === "function" ? await options.headers() : options.headers;
			const headers = new Headers(extra);
			let body: string | undefined;
			if (input.body !== undefined) {
				headers.set("Content-Type", "application/json");
				body = JSON.stringify(input.body);
			}

			const res = await doFetch(target, {
				method,
				headers,
				body,
				credentials: options.credentials ?? "include",
			});
			let parsed: unknown = null;
			try {
				parsed = await res.json();
			} catch {
				parsed = null;
			}
			if (res.ok) {
				return { ok: true, status: res.status, data: parsed as never };
			}
			const err = (
				parsed as { error?: { code?: string; message?: string; issues?: unknown } } | null
			)?.error;
			return {
				ok: false,
				status: res.status,
				error: {
					code: err?.code ?? "HTTP_ERROR",
					message: err?.message ?? `Request failed (${res.status})`,
					issues: err?.issues,
				},
			};
		},
	};
}
