import "server-only";

import { buildAuthHeaders } from "./headers.js";
import { refreshSession } from "./refresh.js";
import type { ResolvedAuthConfig } from "./types.js";

// ---------------------------------------------------------------------------
// fetchWithRefresh — REST fetch with 401-retry
// ---------------------------------------------------------------------------

/**
 * Authenticated server-side fetch for REST endpoints with automatic 401-retry.
 *
 * On 401: refreshes the session once and retries. If still 401 after refresh,
 * returns the failed Response — callers decide how to handle.
 *
 * Returns the raw Response. Throws only on network errors.
 */
export async function fetchWithRefresh<TUser>(
	config: ResolvedAuthConfig<TUser>,
	path: string,
	init: RequestInit = {},
): Promise<Response> {
	const url = `${config.backendUrl}${path}`;
	const headers = await buildAuthHeaders(config, { withAuth: true, withCsrf: true });

	const response = await fetch(url, {
		...init,
		headers: { ...headers, ...(init.headers as Record<string, string> | undefined) },
	});

	if (response.status === 401) {
		const refreshed = await refreshSession(config);
		if (refreshed) {
			const newHeaders = await buildAuthHeaders(config, { withAuth: true, withCsrf: true });
			return fetch(url, {
				...init,
				headers: {
					...newHeaders,
					...(init.headers as Record<string, string> | undefined),
				},
			});
		}
	}

	return response;
}

// ---------------------------------------------------------------------------
// graphqlWithRefresh — GraphQL fetch with 401-retry
// ---------------------------------------------------------------------------

interface GraphQLResponse<T> {
	data?: T;
	errors?: Array<{ message: string; extensions?: { code?: string } }>;
}

export class GraphQLRequestError extends Error {
	constructor(
		public readonly errors: Array<{ message: string; extensions?: { code?: string } }>,
		public readonly status: number,
	) {
		super(errors.map((e) => e.message).join("; "));
		this.name = "GraphQLRequestError";
	}
}

interface GraphQLOptions {
	graphqlUrl?: string;
	/** Additional HTTP headers to merge in. */
	extraHeaders?: Record<string, string>;
}

/**
 * Executes a GraphQL request against the backend, with 401-retry on auth failure.
 *
 * Uses the GraphQL endpoint derived from config.backendUrl + "/graphql" unless
 * opts.graphqlUrl is specified. Throws GraphQLRequestError on GraphQL errors.
 */
export async function graphqlWithRefresh<T, TUser>(
	config: ResolvedAuthConfig<TUser>,
	document: string,
	variables?: Record<string, unknown>,
	opts?: GraphQLOptions,
): Promise<T> {
	const graphqlUrl = opts?.graphqlUrl ?? `${config.backendUrl}/graphql`;

	const _doRequest = async (): Promise<Response> => {
		const headers = await buildAuthHeaders(config, { withAuth: true, withCsrf: true });
		return fetch(graphqlUrl, {
			method: "POST",
			headers: {
				...headers,
				...(opts?.extraHeaders ?? {}),
			},
			body: JSON.stringify({ query: document, variables }),
			cache: "no-store",
		});
	};

	let response = await _doRequest();

	if (response.status === 401) {
		const refreshed = await refreshSession(config);
		if (refreshed) {
			response = await _doRequest();
		}
	}

	const body = (await response.json()) as GraphQLResponse<T>;

	if (body.errors && body.errors.length > 0) {
		throw new GraphQLRequestError(body.errors, response.status);
	}

	if (!body.data) {
		throw new GraphQLRequestError(
			[{ message: "GraphQL response missing data field" }],
			response.status,
		);
	}

	return body.data;
}
