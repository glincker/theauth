/** Passkey (WebAuthn Level 2) authentication, implemented on Web Crypto without external libraries. */

import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { passkeyCredentials } from "../db/schema.js";
import { createPasskeyAuthentication } from "./passkey-authentication.js";
import { getPathSegments, jsonResponse, parseBody } from "./passkey-helpers.js";
import { createPasskeyRegistration } from "./passkey-registration.js";
import type {
	PasskeyConfig,
	PasskeyContext,
	PasskeyCredential,
	PasskeyModule,
} from "./passkey-types.js";
import { PasskeyError } from "./passkey-types.js";
import type { ModuleRequestDeps } from "./request-user.js";
import { authenticationRequired, requestUserId } from "./request-user.js";

export type { PasskeyConfig, PasskeyCredential, PasskeyModule } from "./passkey-types.js";
export { PASSKEY_ERROR, PasskeyError } from "./passkey-types.js";

const MAX_CHALLENGE_TIMEOUT = 300_000;

const DEFAULT_CHALLENGE_TIMEOUT = 60_000;

export function createPasskeyModule(
	config: PasskeyConfig,
	db: Database,
	deps: ModuleRequestDeps = {},
): PasskeyModule {
	const timeout = Math.min(
		config.challengeTimeout ?? DEFAULT_CHALLENGE_TIMEOUT,
		MAX_CHALLENGE_TIMEOUT,
	);
	const userVerification = config.userVerification ?? "preferred";
	const attestation = config.attestation ?? "none";

	async function notifyCredentialChange(
		userId: string,
		change: "added" | "removed",
	): Promise<void> {
		if (!config.onCredentialChange) return;
		try {
			await config.onCredentialChange(userId, change);
		} catch {
			// A notification failure must not undo the change.
		}
	}

	const ctx: PasskeyContext = {
		config,
		db,
		timeout,
		userVerification,
		attestation,
		notifyCredentialChange,
	};
	const { getRegistrationOptions, verifyRegistration } = createPasskeyRegistration(ctx);
	const { getAuthenticationOptions, verifyAuthentication } = createPasskeyAuthentication(ctx);

	async function listCredentials(userId: string): Promise<PasskeyCredential[]> {
		const rows = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.userId, userId));

		return rows.map((r) => ({
			id: r.id,
			credentialId: r.credentialId,
			publicKey: r.publicKey,
			counter: r.counter,
			userId: r.userId,
			deviceName: r.deviceName ?? undefined,
			transports: r.transports ? (JSON.parse(r.transports as string) as string[]) : undefined,
			createdAt: r.createdAt,
			lastUsedAt: r.lastUsedAt,
		}));
	}

	async function removeCredential(credentialId: string, userId: string): Promise<void> {
		await db
			.delete(passkeyCredentials)
			.where(
				and(
					eq(passkeyCredentials.credentialId, credentialId),
					eq(passkeyCredentials.userId, userId),
				),
			);
		await notifyCredentialChange(userId, "removed");
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const method = request.method.toUpperCase();
		const segments = getPathSegments(url);

		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "register" &&
			segments[3] === "options"
		) {
			// Registration binds a credential to the signed-in user, never to a body `userId`.
			const userId = await requestUserId(request, deps.resolveUser);
			if (!userId) return authenticationRequired();
			const body = await parseBody(request);
			const userName = typeof body.userName === "string" ? body.userName : null;
			if (!userName) return jsonResponse({ error: "userName required" }, 400);
			try {
				const options = await getRegistrationOptions(userId, userName);
				return jsonResponse(options);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to generate options";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 500);
			}
		}

		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "register" &&
			segments[3] === "verify"
		) {
			const userId = await requestUserId(request, deps.resolveUser);
			if (!userId) return authenticationRequired();
			const body = await parseBody(request);

			const resp = body.response as Parameters<PasskeyModule["verifyRegistration"]>[1] | undefined;
			if (!resp) return jsonResponse({ error: "response required" }, 400);

			try {
				const result = await verifyRegistration(userId, resp);
				return jsonResponse(result);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Registration failed";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 400);
			}
		}

		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "login" &&
			segments[3] === "options"
		) {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : undefined;
			try {
				const options = await getAuthenticationOptions(userId);
				return jsonResponse(options);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to generate options";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 500);
			}
		}

		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "login" &&
			segments[3] === "verify"
		) {
			const body = await parseBody(request);
			const resp = body.response as
				| Parameters<PasskeyModule["verifyAuthentication"]>[0]
				| undefined;
			if (!resp) return jsonResponse({ error: "response required" }, 400);

			try {
				const result = await verifyAuthentication(resp);
				return jsonResponse(result);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Authentication failed";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 401);
			}
		}

		if (
			method === "GET" &&
			segments.length === 3 &&
			segments[1] === "passkey" &&
			segments[2] === "credentials"
		) {
			const userId = await requestUserId(request, deps.resolveUser);
			if (!userId) return authenticationRequired();

			try {
				const creds = await listCredentials(userId);
				return jsonResponse({ credentials: creds });
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to list credentials";
				return jsonResponse({ error: message }, 500);
			}
		}

		if (
			method === "DELETE" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "credentials"
		) {
			const credentialId = segments[3];
			if (!credentialId) return jsonResponse({ error: "Credential ID required" }, 400);

			const userId = await requestUserId(request, deps.resolveUser);
			if (!userId) return authenticationRequired();

			try {
				await removeCredential(credentialId, userId);
				return jsonResponse({ removed: true });
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to remove credential";
				return jsonResponse({ error: message }, 500);
			}
		}

		return null;
	}

	return {
		getRegistrationOptions,
		verifyRegistration,
		getAuthenticationOptions,
		verifyAuthentication,
		listCredentials,
		removeCredential,
		handleRequest,
	};
}
