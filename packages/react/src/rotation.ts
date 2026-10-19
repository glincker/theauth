import type { RotateErrorCode, RotateResult, RotateRetryConfig, TheAuthUser } from "./types.js";

export const DEFAULT_PROACTIVE_LEAD_MS = 120_000;
export const DEFAULT_RETRY: Required<RotateRetryConfig> = {
	maxRetries: 3,
	initialDelayMs: 1_000,
	backoffMultiplier: 2,
	maxDelayMs: 10_000,
	requestTimeoutMs: 15_000,
};

export const AUTH_ERROR_CODES: ReadonlySet<RotateErrorCode> = new Set([
	"token_missing",
	"token_not_found",
	"token_expired",
	"token_reuse",
	"family_revoked",
	"absolute_timeout",
]);

export const KNOWN_SERVER_CODES: ReadonlySet<RotateErrorCode> = new Set([
	"token_missing",
	"token_not_found",
	"token_expired",
	"token_reuse",
	"family_revoked",
	"absolute_timeout",
]);

export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export function makeNoopRotation(message: string): () => Promise<RotateResult> {
	return async (): Promise<RotateResult> => ({
		success: false,
		code: "network_error",
		message,
	});
}

export function defaultMapUser(data: Record<string, unknown>): TheAuthUser {
	return {
		id: (data.user_id as string) ?? (data.id as string) ?? (data.sub as string) ?? "unknown",
		email: data.email as string | undefined,
		name: data.name as string | undefined,
		image: (data.avatar as string | undefined) ?? (data.image as string | undefined),
	};
}

export interface RotationAttemptContext {
	apiUrl: string;
	refreshPath: string | undefined;
	rotationEnabled: boolean;
	retryCfg: Required<RotateRetryConfig>;
	proactiveLeadMs: number;
	mapServerCode: (raw: unknown) => RotateErrorCode;
	/** Called when an attempt is skipped because the browser is offline. */
	onQueuedOffline: () => void;
}

/** One rotation request, retrying server and network failures with backoff. */
export async function performRotationAttempt(
	ctx: RotationAttemptContext,
	attempt: number,
): Promise<RotateResult> {
	const { apiUrl, refreshPath, rotationEnabled, retryCfg, proactiveLeadMs, mapServerCode } = ctx;
	if (typeof window === "undefined" || !rotationEnabled) {
		return {
			success: false,
			code: "network_error",
			message: "Rotation unavailable",
		};
	}

	if (typeof navigator !== "undefined" && !navigator.onLine) {
		ctx.onQueuedOffline();
		return {
			success: false,
			code: "network_error",
			message: "Offline",
		};
	}

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), retryCfg.requestTimeoutMs);

	try {
		const res = await fetch(`${apiUrl}${refreshPath}`, {
			method: "POST",
			credentials: "include",
			signal: controller.signal,
			headers: { "X-Retry-Attempt": String(attempt) },
		});

		clearTimeout(timeoutId);

		if (res.ok) {
			let parsed: { accessTokenExpiresAt?: string } = {};
			try {
				parsed = (await res.json()) as { accessTokenExpiresAt?: string };
			} catch {
				// Tolerate empty body: server may rotate via cookies only.
			}
			const expiresAt = parsed.accessTokenExpiresAt ? new Date(parsed.accessTokenExpiresAt) : null;
			if (expiresAt && !Number.isNaN(expiresAt.getTime())) {
				return { success: true, accessTokenExpiresAt: expiresAt };
			}
			// No usable expiry: still success, but the next rotation cannot be scheduled.
			return {
				success: true,
				accessTokenExpiresAt: new Date(Date.now() + proactiveLeadMs * 5),
			};
		}

		let body: { error?: unknown } = {};
		try {
			body = (await res.json()) as { error?: unknown };
		} catch {}

		if (res.status === 401) {
			const code = mapServerCode(body.error);
			return {
				success: false,
				code,
				message: typeof body.error === "string" ? body.error : "Unauthorized",
			};
		}

		if (res.status >= 500) {
			if (attempt < retryCfg.maxRetries) {
				const delay = Math.min(
					retryCfg.initialDelayMs * retryCfg.backoffMultiplier ** (attempt - 1),
					retryCfg.maxDelayMs,
				);
				await sleep(delay);
				return performRotationAttempt(ctx, attempt + 1);
			}
			return {
				success: false,
				code: "server_error",
				message: `Server error (${res.status})`,
			};
		}

		return {
			success: false,
			code: "unknown",
			message: `Unexpected status ${res.status}`,
		};
	} catch (error) {
		clearTimeout(timeoutId);

		const isAbort = error instanceof DOMException && error.name === "AbortError";
		const isNetwork = error instanceof TypeError || isAbort;

		if (isNetwork && attempt < retryCfg.maxRetries) {
			const delay = Math.min(
				retryCfg.initialDelayMs * retryCfg.backoffMultiplier ** (attempt - 1),
				retryCfg.maxDelayMs,
			);
			await sleep(delay);
			return performRotationAttempt(ctx, attempt + 1);
		}

		return {
			success: false,
			code: isNetwork ? "network_error" : "unknown",
			message: error instanceof Error ? error.message : "Unknown error",
		};
	}
}
