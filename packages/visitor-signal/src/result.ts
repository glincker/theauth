import type { Result } from "./types.js";

export const ok = <T>(data: T): Result<T> => ({ success: true, data });

export const fail = <T>(code: string, message: string): Result<T> => ({
	success: false,
	error: { code, message },
});

/** Run a source under a timeout. Never throws, a hang or throw becomes a failed result. */
export const runSource = async <T>(
	name: string,
	source: () => Promise<Result<T>>,
	timeoutMs: number,
): Promise<Result<T>> => {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<Result<T>>((resolve) => {
		timer = setTimeout(() => resolve(fail("timeout", `${name} timed out`)), timeoutMs);
	});
	const guarded = (async (): Promise<Result<T>> => {
		try {
			return await source();
		} catch (err) {
			return fail("source_error", err instanceof Error ? err.message : `${name} failed`);
		}
	})();
	try {
		return await Promise.race([guarded, timeout]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
};
