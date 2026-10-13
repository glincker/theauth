import type { ActionResult, PasskeyAuthenticator, TheAuthSession } from "./types.js";

type FetchFn = typeof fetch;

interface ErrorBody {
	error?: string | { message?: string; code?: string };
	challenge?: string;
	gate?: string;
}

function messageOf(body: ErrorBody | null, fallback: string): string {
	const err = body?.error;
	if (typeof err === "string") return err;
	return err?.message ?? fallback;
}

async function readJson<T>(res: Response): Promise<T | null> {
	try {
		return (await res.json()) as T;
	} catch {
		return null;
	}
}

/**
 * Sign in with a passkey: fetch the challenge, let the platform authenticator
 * sign it, and trade the assertion for a session.
 */
export async function runPasskeySignIn(
	base: string,
	authenticator: PasskeyAuthenticator,
	fetchFn: FetchFn,
	userId?: string,
): Promise<ActionResult<TheAuthSession>> {
	try {
		const optionsRes = await fetchFn(`${base}/auth/passkey/authenticate/options`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(userId ? { userId } : {}),
		});
		const options = await readJson<Record<string, unknown> & ErrorBody>(optionsRes);
		if (!optionsRes.ok || !options) {
			return { success: false, error: messageOf(options, "Could not start passkey sign-in") };
		}

		let assertion: Record<string, unknown>;
		try {
			assertion = await authenticator.get(options);
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Passkey sign-in was cancelled",
			};
		}

		const verifyRes = await fetchFn(`${base}/auth/passkey/authenticate/verify`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ response: assertion }),
		});
		const body = await readJson<
			{
				user?: { id: string };
				session?: { token: string; expiresAt?: string };
			} & ErrorBody
		>(verifyRes);
		if (!verifyRes.ok || !body?.session || !body.user) {
			const gated = body?.gate ?? (body?.challenge ? "verification" : null);
			if (gated) return { success: false, error: `Additional verification required (${gated})` };
			return {
				success: false,
				error: messageOf(body, `Passkey sign-in failed (${verifyRes.status})`),
			};
		}
		return {
			success: true,
			data: {
				token: body.session.token,
				user: { id: body.user.id },
				expiresAt: body.session.expiresAt,
			},
		};
	} catch (err) {
		return { success: false, error: err instanceof Error ? err.message : "Network error" };
	}
}

/** Add a passkey to the signed-in user. */
export async function runPasskeyRegistration(
	base: string,
	authenticator: PasskeyAuthenticator,
	fetchFn: FetchFn,
	sessionToken: string,
	deviceName?: string,
): Promise<ActionResult> {
	const headers = {
		"Content-Type": "application/json",
		Authorization: `Bearer ${sessionToken}`,
	};
	try {
		const optionsRes = await fetchFn(`${base}/auth/passkey/register/options`, {
			method: "POST",
			headers,
			body: "{}",
		});
		const options = await readJson<Record<string, unknown> & ErrorBody>(optionsRes);
		if (!optionsRes.ok || !options) {
			return { success: false, error: messageOf(options, "Could not start passkey setup") };
		}

		let attestation: Record<string, unknown>;
		try {
			attestation = await authenticator.create(options);
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Passkey setup was cancelled",
			};
		}

		const verifyRes = await fetchFn(`${base}/auth/passkey/register/verify`, {
			method: "POST",
			headers,
			body: JSON.stringify({ response: { ...attestation, ...(deviceName ? { deviceName } : {}) } }),
		});
		if (!verifyRes.ok) {
			const body = await readJson<ErrorBody>(verifyRes);
			return {
				success: false,
				error: messageOf(body, `Passkey setup failed (${verifyRes.status})`),
			};
		}
		return { success: true, data: undefined };
	} catch (err) {
		return { success: false, error: err instanceof Error ? err.message : "Network error" };
	}
}
