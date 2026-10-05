import type { BootstrapStatus } from "@glinr/theauth-client";
import { useQuery } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

/** `needsSetup` is true until the first user exists. The route is absent unless bootstrap is configured. */
export function useBootstrapStatus() {
	const client = useTheAuthGoClient();
	return useQuery<BootstrapStatus>({
		queryKey: authKeys.bootstrap(),
		queryFn: async () => unwrap(await client.bootstrap.status()),
		retry: false,
	});
}
