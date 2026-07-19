import { TheAuthApiError } from "./error.js";
import type {
	Agent,
	AgentFilters,
	AuditEntry,
	AuditFilters,
	AuthorizeByTokenInput,
	AuthorizeResult,
	CreateAgentInput,
	DelegateInput,
	DelegationChain,
	ExportOptions,
	McpServer,
	Permission,
	RegisterMcpServerInput,
	UpdateAgentInput,
} from "./types.js";

// ─── Client config ────────────────────────────────────────────────────────────

export interface TheAuthClientOptions {
	baseUrl: string;
	/** Bearer token sent as `Authorization: Bearer <token>` on every request. */
	token?: string;
	/** Additional headers merged into every request. */
	headers?: Record<string, string>;
}

// ─── Authorize input (no agentId – passed as path param) ─────────────────────

export interface AuthorizeRequest {
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
}

// ─── Client interface ─────────────────────────────────────────────────────────

export interface TheAuthClient {
	agents: {
		create: (input: CreateAgentInput) => Promise<Agent>;
		list: (filters?: AgentFilters) => Promise<Agent[]>;
		get: (id: string) => Promise<Agent | null>;
		update: (id: string, input: UpdateAgentInput) => Promise<Agent>;
		revoke: (id: string) => Promise<void>;
		rotate: (id: string) => Promise<Agent>;
	};
	/** Authorize an action by agent ID. Calls POST /agents/:id/authorize. */
	authorize: (agentId: string, request: AuthorizeRequest) => Promise<AuthorizeResult>;
	/** Authorize an action using the agent's bearer token. Calls POST /authorize. */
	authorizeByToken: (token: string, request: AuthorizeByTokenInput) => Promise<AuthorizeResult>;
	delegations: {
		create: (input: DelegateInput) => Promise<DelegationChain>;
		list: (agentId: string) => Promise<DelegationChain[]>;
		revoke: (id: string) => Promise<void>;
		getEffectivePermissions: (agentId: string) => Promise<Permission[]>;
	};
	audit: {
		query: (filters?: AuditFilters) => Promise<AuditEntry[]>;
		export: (options: ExportOptions) => Promise<string>;
	};
	mcp: {
		register: (input: RegisterMcpServerInput) => Promise<McpServer>;
		list: () => Promise<McpServer[]>;
		get: (id: string) => Promise<McpServer | null>;
	};
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function buildQuery(params: Record<string, string | number | string[] | undefined>): string {
	const parts: string[] = [];
	for (const [key, value] of Object.entries(params)) {
		if (value === undefined) continue;
		if (Array.isArray(value)) {
			if (value.length > 0) {
				parts.push(`${key}=${encodeURIComponent(value.join(","))}`);
			}
		} else {
			parts.push(`${key}=${encodeURIComponent(String(value))}`);
		}
	}
	return parts.length > 0 ? `?${parts.join("&")}` : "";
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export function createTheAuthClient(options: TheAuthClientOptions): TheAuthClient {
	const base = options.baseUrl.replace(/\/$/, "");

	function buildHeaders(overrides?: Record<string, string>): Record<string, string> {
		const headers: Record<string, string> = {
			"Content-Type": "application/json",
			...options.headers,
		};
		if (options.token) {
			headers.Authorization = `Bearer ${options.token}`;
		}
		if (overrides) {
			Object.assign(headers, overrides);
		}
		return headers;
	}

	async function doFetch<T>(
		path: string,
		init: RequestInit & { extraHeaders?: Record<string, string> } = {},
	): Promise<T> {
		const { extraHeaders, ...fetchInit } = init;
		const headers = buildHeaders(extraHeaders);
		let response: Response;
		try {
			response = await fetch(`${base}${path}`, { ...fetchInit, headers });
		} catch (err) {
			const message = err instanceof Error ? err.message : "Network request failed";
			throw new TheAuthApiError({ code: "NETWORK_ERROR", message }, 0);
		}

		// 204 No Content — nothing to parse
		if (response.status === 204) {
			return undefined as unknown as T;
		}

		// Try to parse JSON body for both success and error cases
		let body: unknown;
		let parseOk = true;
		try {
			body = await response.json();
		} catch {
			parseOk = false;
		}

		if (!response.ok) {
			if (parseOk && body !== null && typeof body === "object") {
				const errBody = body as Record<string, unknown>;
				// Support both { code, message } and { error: { code, message } } shapes
				const inner =
					typeof errBody.error === "object" && errBody.error !== null
						? (errBody.error as Record<string, unknown>)
						: errBody;
				const code = typeof inner.code === "string" ? inner.code : "API_ERROR";
				const message =
					typeof inner.message === "string" ? inner.message : `HTTP ${response.status}`;
				throw new TheAuthApiError({ code, message }, response.status);
			}
			throw new TheAuthApiError(
				{ code: "API_ERROR", message: `HTTP ${response.status}` },
				response.status,
			);
		}

		return body as T;
	}

	async function fetchJson<T>(
		path: string,
		init?: RequestInit & { extraHeaders?: Record<string, string> },
	): Promise<T> {
		return doFetch<T>(path, init);
	}

	async function fetchNullable<T>(path: string, init?: RequestInit): Promise<T | null> {
		try {
			return await fetchJson<T>(path, init);
		} catch (err) {
			if (err instanceof TheAuthApiError && err.status === 404) {
				return null;
			}
			throw err;
		}
	}

	async function fetchRaw(path: string, init?: RequestInit): Promise<string> {
		const headers = buildHeaders();
		let response: Response;
		try {
			response = await fetch(`${base}${path}`, { ...init, headers });
		} catch (err) {
			const message = err instanceof Error ? err.message : "Network request failed";
			throw new TheAuthApiError({ code: "NETWORK_ERROR", message }, 0);
		}

		if (!response.ok) {
			let body: unknown;
			try {
				body = await response.json();
			} catch {
				throw new TheAuthApiError(
					{ code: "API_ERROR", message: `HTTP ${response.status}` },
					response.status,
				);
			}
			const errBody = body as Record<string, unknown>;
			const inner =
				typeof errBody.error === "object" && errBody.error !== null
					? (errBody.error as Record<string, unknown>)
					: errBody;
			const code = typeof inner.code === "string" ? inner.code : "API_ERROR";
			const message = typeof inner.message === "string" ? inner.message : `HTTP ${response.status}`;
			throw new TheAuthApiError({ code, message }, response.status);
		}

		return response.text();
	}

	return {
		// ── Agents ─────────────────────────────────────────────────────────────

		agents: {
			create(input: CreateAgentInput) {
				return fetchJson<Agent>("/agents", {
					method: "POST",
					body: JSON.stringify(input),
				});
			},

			list(filters?: AgentFilters) {
				const qs = filters
					? buildQuery({
							userId: filters.userId,
							status: filters.status,
							type: filters.type,
						})
					: "";
				return fetchJson<Agent[]>(`/agents${qs}`);
			},

			get(id: string) {
				return fetchNullable<Agent>(`/agents/${encodeURIComponent(id)}`);
			},

			update(id: string, input: UpdateAgentInput) {
				return fetchJson<Agent>(`/agents/${encodeURIComponent(id)}`, {
					method: "PATCH",
					body: JSON.stringify(input),
				});
			},

			async revoke(id: string) {
				await fetchJson<void>(`/agents/${encodeURIComponent(id)}`, {
					method: "DELETE",
				});
			},

			rotate(id: string) {
				return fetchJson<Agent>(`/agents/${encodeURIComponent(id)}/rotate`, {
					method: "POST",
				});
			},
		},

		// ── Authorization ───────────────────────────────────────────────────────

		authorize(agentId: string, request: AuthorizeRequest) {
			return fetchJson<AuthorizeResult>(`/agents/${encodeURIComponent(agentId)}/authorize`, {
				method: "POST",
				body: JSON.stringify(request),
			});
		},

		authorizeByToken(token: string, request: AuthorizeByTokenInput) {
			return fetchJson<AuthorizeResult>("/authorize", {
				method: "POST",
				body: JSON.stringify(request),
				// override the client-level token with the agent-specific token
				extraHeaders: { Authorization: `Bearer ${token}` },
			});
		},

		// ── Delegations ─────────────────────────────────────────────────────────

		delegations: {
			create(input: DelegateInput) {
				return fetchJson<DelegationChain>("/delegations", {
					method: "POST",
					body: JSON.stringify(input),
				});
			},

			list(agentId: string) {
				return fetchJson<DelegationChain[]>(`/delegations/${encodeURIComponent(agentId)}`);
			},

			async revoke(id: string) {
				await fetchJson<void>(`/delegations/${encodeURIComponent(id)}`, {
					method: "DELETE",
				});
			},

			getEffectivePermissions(agentId: string) {
				return fetchJson<Permission[]>(`/delegations/${encodeURIComponent(agentId)}/permissions`);
			},
		},

		// ── Audit ───────────────────────────────────────────────────────────────

		audit: {
			query(filters?: AuditFilters) {
				const qs = filters
					? buildQuery({
							agentId: filters.agentId,
							userId: filters.userId,
							since: filters.since,
							until: filters.until,
							actions: filters.actions,
							result: filters.result,
							limit: filters.limit,
							offset: filters.offset,
						})
					: "";
				return fetchJson<AuditEntry[]>(`/audit${qs}`);
			},

			export(options: ExportOptions) {
				const qs = buildQuery({
					format: options.format,
					since: options.since,
					until: options.until,
				});
				return fetchRaw(`/audit/export${qs}`);
			},
		},

		// ── MCP servers ─────────────────────────────────────────────────────────

		mcp: {
			register(input: RegisterMcpServerInput) {
				return fetchJson<McpServer>("/mcp/servers", {
					method: "POST",
					body: JSON.stringify(input),
				});
			},

			list() {
				return fetchJson<McpServer[]>("/mcp/servers");
			},

			get(id: string) {
				return fetchNullable<McpServer>(`/mcp/servers/${encodeURIComponent(id)}`);
			},
		},
	};
}

// ─── Deprecated aliases ─────────────────────────────────────────────────────
// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthClientOptions` instead. Will be removed in a future major version. */
export type AuthClientOptions = TheAuthClientOptions;

/** @deprecated Use `TheAuthClientOptions` instead. Will be removed in a future major version. */
export type KavachClientOptions = TheAuthClientOptions;

/** @deprecated Use `TheAuthClient` instead. Will be removed in a future major version. */
export type AuthClient = TheAuthClient;

/** @deprecated Use `TheAuthClient` instead. Will be removed in a future major version. */
export type KavachClient = TheAuthClient;

/** @deprecated Use `createTheAuthClient` instead. Will be removed in a future major version. */
export const createAuthClient = createTheAuthClient;

/** @deprecated Use `createTheAuthClient` instead. Will be removed in a future major version. */
export const createKavachClient = createTheAuthClient;
