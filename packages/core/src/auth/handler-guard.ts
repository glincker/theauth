/**
 * Fail-closed authentication for the `handleRequest` handlers of the organization and API key modules.
 *
 * Those handlers manage orgs, members and credentials, so they must know who is calling. A module built without an
 * authenticate resolver answers 401 to every route it owns. Trusted server code that calls `handleRequest` behind its
 * own auth can opt out with `trustedServerUse: true`, which restores the old behavior of acting on ids in the request.
 */

import type { ModuleRequestDeps } from "./request-user.js";
import { authenticationRequired, requestUserId } from "./request-user.js";

/** Config shared by the modules guarded here. */
export interface HandlerGuardConfig {
	/**
	 * Opt out of the fail-closed default for `handleRequest`. Only for trusted server use, where your own code has already
	 * authenticated and authorized the caller before it forwards the request. With no resolver and this flag unset,
	 * `handleRequest` answers 401. With a resolver, the flag has no effect and the resolver is always enforced.
	 */
	trustedServerUse?: boolean;
}

export type HandlerActor =
	| { kind: "user"; userId: string }
	| { kind: "trusted" }
	| { kind: "denied"; response: Response };

/** Who is calling: the resolved user, a trusted server caller (explicit opt-out), or a 401 response. */
export async function resolveHandlerActor(
	request: Request,
	deps: ModuleRequestDeps,
	config: HandlerGuardConfig,
): Promise<HandlerActor> {
	if (deps.resolveUser) {
		const userId = await requestUserId(request, deps.resolveUser);
		return userId
			? { kind: "user", userId }
			: { kind: "denied", response: authenticationRequired() };
	}
	if (config.trustedServerUse === true) return { kind: "trusted" };
	return { kind: "denied", response: authenticationRequired() };
}

export function forbidden(): Response {
	return new Response(JSON.stringify({ error: "Forbidden" }), {
		status: 403,
		headers: { "Content-Type": "application/json" },
	});
}
