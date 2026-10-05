import type { ReactNode } from "react";
import { useState } from "react";

export const CODE_RECENT_AUTH_REQUIRED = "auth.recent_auth_required";
const CODE_UNKNOWN = "unknown";

export interface ErrorLabels {
	/** Maps a stable error code (for example `invalid_expiry`) to host copy. */
	error: (code: string) => string;
}

export type ClassNames<Part extends string> = Partial<Record<Part, string>>;

/** Runs an action; a step-up wrapper from `useStepUpRetry` can be passed to retry after elevation. */
export type RunAction = (action: () => Promise<unknown>) => Promise<unknown>;

export function errorCodeOf(error: unknown): string | null {
	if (error === null || error === undefined) return null;
	if (typeof error === "object" && "code" in error) {
		const { code } = error as { code: unknown };
		if (typeof code === "string" && code !== "") return code;
	}
	return CODE_UNKNOWN;
}

export async function exec(run: RunAction | undefined, action: () => Promise<unknown>) {
	try {
		await (run ? run(action) : action());
	} catch {
		// The failing mutation already holds the error; components render its code.
	}
}

export function visibleCode(error: unknown, hasStepUp: boolean): string | null {
	const code = errorCodeOf(error);
	return hasStepUp && code === CODE_RECENT_AUTH_REQUIRED ? null : code;
}

export function ErrorText({
	code,
	labels,
	className,
}: {
	code: string | null;
	labels: ErrorLabels;
	className?: string;
}): ReactNode {
	if (!code) return null;
	return (
		<p role="alert" data-part="error" data-error-code={code} className={className}>
			{labels.error(code)}
		</p>
	);
}

export function CopyButton({
	value,
	label,
	copiedLabel,
	className,
}: {
	value: string;
	label: string;
	copiedLabel: string;
	className?: string;
}) {
	const [copied, setCopied] = useState(false);
	const copy = async () => {
		try {
			await navigator.clipboard.writeText(value);
			setCopied(true);
		} catch {
			setCopied(false);
		}
	};
	return (
		<>
			<button
				type="button"
				data-part="copy"
				data-copied={copied || undefined}
				className={className}
				onClick={copy}
			>
				{label}
			</button>
			<span role="status" aria-live="polite" data-part="copy-status">
				{copied ? copiedLabel : ""}
			</span>
		</>
	);
}
