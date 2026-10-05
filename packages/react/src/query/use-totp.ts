import type { TotpEnrollment, TotpStatus } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

/** Whether TOTP is enrolled and how many recovery codes remain. */
export function useTotpStatus() {
	const client = useTheAuthGoClient();
	return useQuery<TotpStatus>({
		queryKey: authKeys.totp(),
		queryFn: async () => unwrap(await client.totp.status()),
	});
}

export function useTotp() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refreshSession = () => qc.invalidateQueries({ queryKey: authKeys.session() });
	const refreshStatus = () => qc.invalidateQueries({ queryKey: authKeys.totp() });

	const enrollBegin = useMutation<TotpEnrollment, Error, void>({
		mutationFn: async () => unwrap(await client.totp.enrollBegin()),
	});
	const enrollFinish = useMutation<
		{ recoveryCodes: string[] },
		Error,
		{ enrollmentId: string; code: string }
	>({
		mutationFn: async (input) => unwrap(await client.totp.enrollFinish(input)),
		onSuccess: refreshStatus,
	});
	const verify = useMutation<{ ok: true }, Error, string>({
		mutationFn: async (code) => unwrap(await client.totp.verify(code)),
		onSuccess: refreshSession,
	});
	const recovery = useMutation<{ ok: true }, Error, string>({
		mutationFn: async (code) => unwrap(await client.totp.recovery(code)),
		onSuccess: refreshSession,
	});
	const disable = useMutation<null, Error, void>({
		mutationFn: async () => unwrap(await client.totp.disable()),
		onSuccess: refreshStatus,
	});
	const regenerateRecoveryCodes = useMutation<{ recoveryCodes: string[] }, Error, void>({
		mutationFn: async () => unwrap(await client.totp.regenerateRecoveryCodes()),
		onSuccess: refreshStatus,
	});

	return { enrollBegin, enrollFinish, verify, recovery, disable, regenerateRecoveryCodes };
}
