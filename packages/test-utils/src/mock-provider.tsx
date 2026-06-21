/**
 * MockKavachProvider
 *
 * Wraps `KavachContext.Provider` with controlled fake data so component tests
 * can exercise auth-dependent UI without making any network requests.
 *
 * All action methods (signIn, signUp, signOut, refresh) are `vi.fn()` spies
 * by default so you can assert call counts and return values in tests.
 */

import type {
	ActionResult,
	KavachContextValue,
	KavachSession,
	KavachUser,
} from "@glinr/theauth-react";
import { KavachContext } from "@glinr/theauth-react";
import type { ReactNode } from "react";
import { vi } from "vitest";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MockKavachProviderProps {
	children: ReactNode;
	/** The user to expose via `useUser()`. Defaults to `null`. */
	user?: KavachUser | null;
	/** The session to expose via `useSession()`. Defaults to `null`. */
	session?: KavachSession | null;
	/** Override `isAuthenticated`. Defaults to `session !== null`. */
	isAuthenticated?: boolean;
	/** Override `isLoading`. Defaults to `false`. */
	isLoading?: boolean;
	/**
	 * Override the `signIn` spy.
	 * Defaults to `vi.fn()` resolving `{ success: true, data: undefined }`.
	 */
	signIn?: KavachContextValue["signIn"];
	/**
	 * Override the `signUp` spy.
	 * Defaults to `vi.fn()` resolving `{ success: true, data: undefined }`.
	 */
	signUp?: KavachContextValue["signUp"];
	/**
	 * Override the `signOut` spy.
	 * Defaults to `vi.fn()` resolving `undefined`.
	 */
	signOut?: KavachContextValue["signOut"];
	/**
	 * Override the `refresh` spy.
	 * Defaults to `vi.fn()` resolving `undefined`.
	 */
	refresh?: KavachContextValue["refresh"];
}

// ─── Default spies ────────────────────────────────────────────────────────────

function makeDefaultSignIn(): KavachContextValue["signIn"] {
	const spy = vi.fn(
		async (_email: string, _password: string): Promise<ActionResult> => ({
			success: true,
			data: undefined,
		}),
	);
	return spy;
}

function makeDefaultSignUp(): KavachContextValue["signUp"] {
	const spy = vi.fn(
		async (_email: string, _password: string, _name?: string): Promise<ActionResult> => ({
			success: true,
			data: undefined,
		}),
	);
	return spy;
}

function makeDefaultSignOut(): KavachContextValue["signOut"] {
	return vi.fn(async (): Promise<void> => undefined);
}

function makeDefaultRefresh(): KavachContextValue["refresh"] {
	return vi.fn(async (): Promise<void> => undefined);
}

// ─── Component ────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for `<KavachProvider>` in component tests.
 *
 * @example
 * ```tsx
 * const user = createMockUser();
 * const session = createMockSession({ user });
 *
 * render(
 *   <MockKavachProvider user={user} session={session}>
 *     <ProfileButton />
 *   </MockKavachProvider>
 * );
 *
 * expect(screen.getByText(user.name!)).toBeInTheDocument();
 * ```
 */
export function MockKavachProvider({
	children,
	user = null,
	session = null,
	isAuthenticated,
	isLoading = false,
	signIn,
	signUp,
	signOut,
	refresh,
}: MockKavachProviderProps): ReactNode {
	const value: KavachContextValue = {
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

	return <KavachContext.Provider value={value}>{children}</KavachContext.Provider>;
}
