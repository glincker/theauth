import "server-only";

import { buildAuthHeaders } from "./headers.js";
import { refreshSession } from "./refresh.js";
import type { ResolvedAuthConfig } from "./types.js";

/**
 * Server-side REST fetch with one refresh-and-retry on 401. Returns the raw Response,
 * including a failed one after refresh, and throws only on network errors.
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
	extraHeaders?: Record<string, string>;
}

/**
 * Returns true when a parsed GraphQL body signals that the caller is
 * unauthenticated via the error extensions code (HTTP 200 auth errors).
 * Covers both Apollo Server ("UNAUTHENTICATED") and Hasura/GraphQL-Java
 * ("UNAUTHORIZED") conventions.
 */
function isUnauthenticatedGraphQLError(body: GraphQLResponse<unknown>): boolean {
	return Boolean(
		body.errors?.some((e) => {
			const code = (e.extensions as { code?: string } | undefined)?.code;
			return code === "UNAUTHENTICATED" || code === "UNAUTHORIZED";
		}),
	);
}

/**
 * Runs a GraphQL request with one auth retry. Retries on HTTP 401 (WAF or load balancer) and on
 * HTTP 200 with an UNAUTHENTICATED or UNAUTHORIZED error extension. Throws GraphQLRequestError
 * on GraphQL errors or non-JSON bodies.
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

	/**
	 * Parse the response body as JSON, throwing typed errors for:
	 *   - Non-2xx HTTP status (e.g. WAF/load-balancer plain-text 401)
	 *   - Non-JSON body
	 */
	const _parseBody = async (response: Response): Promise<GraphQLResponse<T>> => {
		if (!response.ok) {
			throw new GraphQLRequestError(
				[{ message: `HTTP ${response.status}: ${response.statusText}` }],
				response.status,
			);
		}

		try {
			return (await response.json()) as GraphQLResponse<T>;
		} catch {
			throw new GraphQLRequestError(
				[{ message: `Non-JSON response from GraphQL endpoint (status ${response.status})` }],
				response.status,
			);
		}
	};

	const _validateAndReturn = (body: GraphQLResponse<T>, status: number): T => {
		if (body.errors && body.errors.length > 0) {
			throw new GraphQLRequestError(body.errors, status);
		}
		if (!body.data) {
			throw new GraphQLRequestError([{ message: "GraphQL response missing data field" }], status);
		}
		return body.data;
	};

	const firstResponse = await _doRequest();

	// HTTP 401 from a WAF or load balancer may carry a non-JSON body.
	if (firstResponse.status === 401) {
		const refreshed = await refreshSession(config);
		if (refreshed) {
			const retryResponse = await _doRequest();
			const retryBody = await _parseBody(retryResponse);
			return _validateAndReturn(retryBody, retryResponse.status);
		}
		// Refresh failed, so surface the 401 as a typed error
		throw new GraphQLRequestError(
			[{ message: `HTTP ${firstResponse.status}: ${firstResponse.statusText}` }],
			firstResponse.status,
		);
	}

	const firstBody = await _parseBody(firstResponse);

	if (isUnauthenticatedGraphQLError(firstBody)) {
		const refreshed = await refreshSession(config);
		if (refreshed) {
			const retryResponse = await _doRequest();
			const retryBody = await _parseBody(retryResponse);
			return _validateAndReturn(retryBody, retryResponse.status);
		}
		// Refresh failed, so fall through and throw the original GraphQL errors
	}

	return _validateAndReturn(firstBody, firstResponse.status);
}
