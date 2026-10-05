import type { PasskeyCredential } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

export function usePasskeys() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refresh = () => qc.invalidateQueries({ queryKey: authKeys.passkeys() });

	const list = useQuery<PasskeyCredential[]>({
		queryKey: authKeys.passkeys(),
		queryFn: async () => unwrap(await client.passkeys.list()),
	});
	const register = useMutation<PasskeyCredential, Error, string | undefined>({
		mutationFn: async (name) => unwrap(await client.passkeys.register(name)),
		onSuccess: refresh,
	});
	const remove = useMutation<null, Error, string>({
		mutationFn: async (id) => unwrap(await client.passkeys.remove(id)),
		onSuccess: refresh,
	});
	const rename = useMutation<null, Error, { id: string; name: string }>({
		mutationFn: async ({ id, name }) => unwrap(await client.passkeys.rename(id, name)),
		onSuccess: refresh,
	});
	const login = useMutation<{ ok: true }, Error, void>({
		mutationFn: async () => unwrap(await client.passkeys.login()),
		onSuccess: () => qc.invalidateQueries({ queryKey: authKeys.session() }),
	});

	return { list, register, remove, rename, login, isSupported: client.passkeys.isSupported() };
}
