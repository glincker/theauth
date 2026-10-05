import type { DeviceRequestInfo } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

/**
 * Backs a device verification page. Pass the user code once typed (or taken from the
 * verification URL); `info` stays idle while it is empty.
 */
export function useDeviceApproval(userCode: string) {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const code = userCode.trim();
	const key = authKeys.deviceRequest(code);
	const settle = () => qc.removeQueries({ queryKey: key });

	const info = useQuery<DeviceRequestInfo>({
		queryKey: key,
		queryFn: async () => unwrap(await client.device.info(code)),
		enabled: code.length > 0,
		retry: false,
	});
	const approve = useMutation<null, Error, string[] | undefined>({
		mutationFn: async (abilities) => unwrap(await client.device.approve(code, abilities)),
		onSuccess: settle,
	});
	const deny = useMutation<null, Error, void>({
		mutationFn: async () => unwrap(await client.device.deny(code)),
		onSuccess: settle,
	});

	return { info, approve, deny };
}
