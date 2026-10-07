import type { ReactNode } from "react";
import type { AuthCardProps } from "../types.js";
import { cx } from "../utils.js";

export function AuthCard({
	classNames,
	title,
	description,
	children,
	className,
}: AuthCardProps): ReactNode {
	return (
		<div
			className={cx(
				"theauth-auth-card-root flex min-h-screen items-center justify-center p-4",
				classNames?.root ?? className,
			)}
		>
			<div
				className={cx(
					"theauth-auth-card w-full max-w-sm rounded-xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900",
					classNames?.card,
				)}
			>
				{title && (
					<h2
						className={cx(
							"theauth-auth-card-title mb-1 text-center text-xl font-semibold text-zinc-900 dark:text-zinc-100",
							classNames?.title,
						)}
					>
						{title}
					</h2>
				)}
				{description && (
					<p
						className={cx(
							"theauth-auth-card-desc mb-6 text-center text-sm text-zinc-500 dark:text-zinc-400",
							classNames?.description,
						)}
					>
						{description}
					</p>
				)}
				{!description && title && <div className="mb-6" />}
				{children}
			</div>
		</div>
	);
}
