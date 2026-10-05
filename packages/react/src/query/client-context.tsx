import type { GoAuthError, GoAuthResult, TheAuthGoClient } from "@glinr/theauth-client";
import type { ReactNode } from "react";
import { createContext, createElement, useContext } from "react";

const ClientContext = createContext<TheAuthGoClient | null>(null);

export interface TheAuthQueryProviderProps {
	client: TheAuthGoClient;
	children: ReactNode;
}

export function TheAuthQueryProvider({ client, children }: TheAuthQueryProviderProps) {
	return createElement(ClientContext.Provider, { value: client }, children);
}

export function useTheAuthGoClient(): TheAuthGoClient {
	const client = useContext(ClientContext);
	if (!client) throw new Error("TheAuthQueryProvider is missing");
	return client;
}

/** Thrown by query and mutation functions; `code` is the stable error code to map to copy. */
export class AuthQueryError extends Error {
	readonly code: string;
	readonly status: number;
	readonly retryAfter?: number;

	constructor(error: GoAuthError) {
		super(error.code);
		this.name = "AuthQueryError";
		this.code = error.code;
		this.status = error.status;
		this.retryAfter = error.retryAfter;
	}
}

export function unwrap<T>(result: GoAuthResult<T>): T {
	if (!result.success) throw new AuthQueryError(result.error);
	return result.data;
}
