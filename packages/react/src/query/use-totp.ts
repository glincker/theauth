import type { TotpEnrollment } from "@glinr/theauth-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

export function useTotp() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refreshSession = () => qc.invalidateQueries({ queryKey: authKeys.session() });

	const enrollBegin = useMutation<TotpEnrollment, Error, void>({
		mutationFn: async () => unwrap(await client.totp.enrollBegin()),
	});
	const enrollFinish = useMutation<
		{ recoveryCodes: string[] },
		Error,
		{ enrollmentId: string; code: string }
	>({
		mutationFn: async (input) => unwrap(await client.totp.enrollFinish(input)),
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
	});

	return { enrollBegin, enrollFinish, verify, recovery, disable };
}
