import type { GoUser, LoginResult } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

const HTTP_UNAUTHORIZED = 401;

/** Resolves to the signed-in user, or null when there is no valid session. */
export function useSession() {
	const client = useTheAuthGoClient();
	return useQuery<GoUser | null>({
		queryKey: authKeys.session(),
		queryFn: async () => {
			const res = await client.session.get();
			if (!res.success && res.error.status === HTTP_UNAUTHORIZED) return null;
			return unwrap(res);
		},
		retry: false,
	});
}

export function useLogin() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	return useMutation<LoginResult, Error, { email: string; password: string }>({
		mutationFn: async (input) => unwrap(await client.login(input)),
		onSuccess: () => qc.invalidateQueries({ queryKey: authKeys.session() }),
	});
}

export function useLogout() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	return useMutation<null, Error, void>({
		mutationFn: async () => unwrap(await client.logout()),
		onSuccess: () => {
			qc.setQueryData(authKeys.session(), null);
			return qc.invalidateQueries({ queryKey: authKeys.all });
		},
	});
}

/** The server exposes only the current session today; see MISSING.md in the client package. */
export function useSessions() {
	return { current: useSession(), revokeCurrent: useLogout() };
}
