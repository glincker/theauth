import type { ReactNode } from "react";
import { TheAuthContext, useTheAuthContext } from "./auth-context.js";
import { resolveDebug } from "./debug.js";
import { ExternalProvider } from "./external-provider.js";
import { ManagedProvider } from "./managed-provider.js";
import type { ExternalAuthConfig, ManagedAuthConfig } from "./types.js";

export { TheAuthContext, useTheAuthContext };

export interface TheAuthProviderProps {
	children: ReactNode;
	/** Base path where TheAuth is mounted. Defaults to "/api/theauth". */
	basePath?: string;
	/**
	 * Delegates authentication to an external API. Sessions live in httpOnly cookies,
	 * not localStorage. Paths are joined onto `external.apiUrl`.
	 */
	external?: ExternalAuthConfig;
	/** Options for the built in session store (refetch triggers, SSR seed, route paths). */
	managed?: ManagedAuthConfig;
	/** Logs auth state transitions to the console. Also on when `localStorage.DEBUG === "theauth"`. */
	debug?: boolean;
}

export function TheAuthProvider({
	children,
	basePath = "/api/theauth",
	external,
	managed,
	debug,
}: TheAuthProviderProps): ReactNode {
	const debugEnabled = resolveDebug(debug);
	if (external) {
		return (
			<ExternalProvider config={external} debug={debugEnabled}>
				{children}
			</ExternalProvider>
		);
	}
	return (
		<ManagedProvider basePath={basePath} debug={debugEnabled} managed={managed}>
			{children}
		</ManagedProvider>
	);
}

// Backward-compat aliases for the pre-rebrand API.

/** @deprecated Use `TheAuthContext` instead. Will be removed in a future major version. */
export const AuthContext = TheAuthContext;

/** @deprecated Use `useTheAuthContext` instead. Will be removed in a future major version. */
export const useAuthContext = useTheAuthContext;

/** @deprecated Use `TheAuthProvider` instead. Will be removed in a future major version. */
export const AuthProvider = TheAuthProvider;

/** @deprecated Use `TheAuthProviderProps` instead. Will be removed in a future major version. */
export type AuthProviderProps = TheAuthProviderProps;
