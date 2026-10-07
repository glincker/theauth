/**
 * MockTheAuthProvider
 *
 * Wraps `TheAuthContext.Provider` with controlled fake data so component tests
 * can exercise auth-dependent UI without making any network requests.
 *
 * All action methods (signIn, signUp, signOut, refresh) are `vi.fn()` spies
 * by default so you can assert call counts and return values in tests.
 */

import type {
	ActionResult,
	TheAuthContextValue,
	TheAuthSession,
	TheAuthUser,
} from "@glinr/theauth-react";
import { TheAuthContext } from "@glinr/theauth-react";
import type { ReactNode } from "react";
import { vi } from "vitest";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MockTheAuthProviderProps {
	children: ReactNode;
	/** The user to expose via `useUser()`. Defaults to `null`. */
	user?: TheAuthUser | null;
	/** The session to expose via `useSession()`. Defaults to `null`. */
	session?: TheAuthSession | null;
	/** Override `isAuthenticated`. Defaults to `session !== null`. */
	isAuthenticated?: boolean;
	/** Override `isLoading`. Defaults to `false`. */
	isLoading?: boolean;
	/**
	 * Override the `signIn` spy.
	 * Defaults to `vi.fn()` resolving `{ success: true, data: undefined }`.
	 */
	signIn?: TheAuthContextValue["signIn"];
	/**
	 * Override the `signUp` spy.
	 * Defaults to `vi.fn()` resolving `{ success: true, data: undefined }`.
	 */
	signUp?: TheAuthContextValue["signUp"];
	/**
	 * Override the `signOut` spy.
	 * Defaults to `vi.fn()` resolving `undefined`.
	 */
	signOut?: TheAuthContextValue["signOut"];
	/**
	 * Override the `refresh` spy.
	 * Defaults to `vi.fn()` resolving `undefined`.
	 */
	refresh?: TheAuthContextValue["refresh"];
}

// ─── Default spies ────────────────────────────────────────────────────────────

function makeDefaultSignIn(): TheAuthContextValue["signIn"] {
	const spy = vi.fn(
		async (_email: string, _password: string): Promise<ActionResult> => ({
			success: true,
			data: undefined,
		}),
	);
	return spy;
}

function makeDefaultSignUp(): TheAuthContextValue["signUp"] {
	const spy = vi.fn(
		async (_email: string, _password: string, _name?: string): Promise<ActionResult> => ({
			success: true,
			data: undefined,
		}),
	);
	return spy;
}

function makeDefaultSignOut(): TheAuthContextValue["signOut"] {
	return vi.fn(async (): Promise<void> => undefined);
}

function makeDefaultRefresh(): TheAuthContextValue["refresh"] {
	return vi.fn(async (): Promise<void> => undefined);
}

// ─── Component ────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for `<TheAuthProvider>` in component tests.
 *
 * @example
 * ```tsx
 * const user = createMockUser();
 * const session = createMockSession({ user });
 *
 * render(
 *   <MockTheAuthProvider user={user} session={session}>
 *     <ProfileButton />
 *   </MockTheAuthProvider>
 * );
 *
 * expect(screen.getByText(user.name!)).toBeInTheDocument();
 * ```
 */
export function MockTheAuthProvider({
	children,
	user = null,
	session = null,
	isAuthenticated,
	isLoading = false,
	signIn,
	signUp,
	signOut,
	refresh,
}: MockTheAuthProviderProps): ReactNode {
	const value: TheAuthContextValue = {
		user,
		session,
		isLoading,
		isAuthenticated: isAuthenticated ?? session !== null,
		signIn: signIn ?? makeDefaultSignIn(),
		signUp: signUp ?? makeDefaultSignUp(),
		signOut: signOut ?? makeDefaultSignOut(),
		refresh: refresh ?? makeDefaultRefresh(),
		// v0.5 rotation surface — managed-mode no-ops in tests by default.
		rotateSession: async () => ({
			success: false,
			code: "network_error",
			message: "rotateSession not mocked",
		}),
		rotationStatus: "idle",
		isOnline: true,
	};

	return <TheAuthContext.Provider value={value}>{children}</TheAuthContext.Provider>;
}
