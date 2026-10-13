import type { ReactNode } from "react";
import { useId } from "react";
import type {
	ButtonSlotProps,
	DividerSlotProps,
	ErrorSlotProps,
	InputSlotProps,
} from "../types.js";

/**
 * Default slot implementations shared by the auth components. Hosts replace
 * any of them through the `components` prop.
 */

export function Spinner(): ReactNode {
	return (
		<svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
			<circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
			<path
				className="opacity-75"
				fill="currentColor"
				d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
			/>
		</svg>
	);
}

export function DefaultInput({ label, error, ...rest }: InputSlotProps): ReactNode {
	const errorId = useId();
	return (
		<label className="theauth-field flex flex-col gap-1.5">
			<span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
			<input
				aria-invalid={error ? true : undefined}
				aria-describedby={error ? errorId : undefined}
				{...rest}
				className={
					rest.className ??
					"theauth-input w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition-colors placeholder:text-zinc-400 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
				}
			/>
			{error && (
				<p id={errorId} role="alert" className="text-xs text-red-500">
					{error}
				</p>
			)}
		</label>
	);
}

export function DefaultButton({ loading, children, ...rest }: ButtonSlotProps): ReactNode {
	return (
		<button
			{...rest}
			disabled={rest.disabled ?? loading}
			aria-busy={loading ? true : undefined}
			className={
				rest.className ??
				"theauth-btn w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
			}
		>
			{loading ? (
				<span className="flex items-center justify-center gap-2">
					<Spinner />
					{children}
				</span>
			) : (
				children
			)}
		</button>
	);
}

export function DefaultDivider({ label, className }: DividerSlotProps): ReactNode {
	return (
		<div className={className ?? "theauth-divider flex items-center gap-3 py-1"}>
			<div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
			{label && <span className="text-xs text-zinc-400">{label}</span>}
			<div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
		</div>
	);
}

/** `role="alert"` makes assistive tech announce the message when it appears. */
export function DefaultError({ message, className }: ErrorSlotProps): ReactNode {
	return (
		<div
			role="alert"
			className={
				className ??
				"theauth-error rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
			}
		>
			{message}
		</div>
	);
}
