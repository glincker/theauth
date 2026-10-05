import type { GoSession, GoUser, LoginResult, SignupInput } from "@glinr/theauth-client";
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

/** The caller's own sessions, plus revoke one, revoke all others, and revoke the current one. */
export function useSessions() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refresh = () => qc.invalidateQueries({ queryKey: authKeys.sessions() });

	const list = useQuery<GoSession[]>({
		queryKey: authKeys.sessions(),
		queryFn: async () => unwrap(await client.session.list()),
	});
	const revoke = useMutation<null, Error, string>({
		mutationFn: async (id) => unwrap(await client.session.revoke(id)),
		onSuccess: () =>
			Promise.all([refresh(), qc.invalidateQueries({ queryKey: authKeys.session() })]),
	});
	const revokeOthers = useMutation<{ revoked: number }, Error, void>({
		mutationFn: async () => unwrap(await client.session.revokeOthers()),
		onSuccess: refresh,
	});

	return { list, revoke, revokeOthers, current: useSession(), revokeCurrent: useLogout() };
}

export function useSignup() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	return useMutation<{ ok: true }, Error, SignupInput>({
		mutationFn: async (input) => unwrap(await client.signup(input)),
		onSuccess: () => qc.invalidateQueries({ queryKey: authKeys.bootstrap() }),
	});
}

export function useChangePassword() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	return useMutation<null, Error, { currentPassword: string; newPassword: string }>({
		mutationFn: async (input) => unwrap(await client.changePassword(input)),
		onSuccess: () => qc.invalidateQueries({ queryKey: authKeys.sessions() }),
	});
}
