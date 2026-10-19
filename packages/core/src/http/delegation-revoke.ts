import { failure, noContent } from "./respond.js";

/**
 * The one response for revoking a delegation chain, used by the core route table and the admin
 * plugin so both mounts of `DELETE /delegations/:id` answer alike: 204 with no body on success,
 * 404 for an unknown chain, 500 with a fixed message otherwise. `onRevoked` receives the ids of
 * every link the revoke cut (the chain and its descendants), for audit.
 */
export async function revokeDelegationResponse(
	revoke: () => Promise<unknown>,
	onRevoked?: (revoked: string[]) => Promise<void>,
): Promise<Response> {
	try {
		const revoked = await revoke();
		if (onRevoked) await onRevoked(Array.isArray(revoked) ? (revoked as string[]) : []);
		return noContent();
	} catch (err) {
		return failure(err, "Failed to revoke delegation");
	}
}
