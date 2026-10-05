import type { StepUpProof, StepUpResult } from "@glinr/theauth-client";
import { useMutation } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";

/**
 * Re-prove identity after a 403 auth.recent_auth_required, then retry the original action.
 * `elevatedUntil` on a result is when the fresh-auth window closes.
 */
export function useStepUp() {
	const client = useTheAuthGoClient();
	const verify = useMutation<StepUpResult, Error, StepUpProof>({
		mutationFn: async (proof) => unwrap(await client.stepUp.verify(proof)),
	});
	const passkey = useMutation<StepUpResult, Error, void>({
		mutationFn: async () => unwrap(await client.stepUp.passkey()),
	});
	return { verify, passkey, isPasskeySupported: client.passkeys.isSupported() };
}
