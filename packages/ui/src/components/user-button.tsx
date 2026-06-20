import { useSignOut, useUser } from "@theauth/react";
import type { ReactNode } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import type { AvatarSlotProps, UserButtonProps } from "../types.js";
import { cx } from "../utils.js";

// ─── Default avatar ──────────────────────────────────────────────────────────

function DefaultAvatar({ src, name, className }: AvatarSlotProps): ReactNode {
	if (src) {
		return (
			<img
				src={src}
				alt={name ?? "User avatar"}
				className={className ?? "kavach-avatar h-8 w-8 rounded-full object-cover"}
			/>
		);
	}

	const initials = (name ?? "U")
		.split(" ")
		.map((w) => w[0])
		.join("")
		.slice(0, 2)
		.toUpperCase();

	return (
		<div
			className={
				className ??
				"kavach-avatar flex h-8 w-8 items-center justify-center rounded-full bg-zinc-200 text-xs font-semibold text-zinc-600 dark:bg-zinc-700 dark:text-zinc-300"
			}
		>
			{initials}
		</div>
	);
}

// ─── Component ───────────────────────────────────────────────────────────────

export function UserButton({
	classNames,
	components,
	menuItems = [],
	onSignOut,
	showEmail = true,
	className,
}: UserButtonProps): ReactNode {
	const { user, isAuthenticated } = useUser();
	const { signOut } = useSignOut();
	const [open, setOpen] = useState(false);
	const ref = useRef<HTMLDivElement>(null);

	const Avatar = components?.Avatar ?? DefaultAvatar;

	// Close on outside click
	useEffect(() => {
		function handleClickOutside(e: MouseEvent) {
			if (ref.current && !ref.current.contains(e.target as Node)) {
				setOpen(false);
			}
		}
		if (open) {
			document.addEventListener("mousedown", handleClickOutside);
			return () => document.removeEventListener("mousedown", handleClickOutside);
		}
	}, [open]);

	// Close on escape
	useEffect(() => {
		function handleEscape(e: KeyboardEvent) {
			if (e.key === "Escape") setOpen(false);
		}
		if (open) {
			document.addEventListener("keydown", handleEscape);
			return () => document.removeEventListener("keydown", handleEscape);
		}
	}, [open]);

	const handleSignOut = useCallback(async () => {
		setOpen(false);
		await signOut();
		onSignOut?.();
	}, [signOut, onSignOut]);

	if (!isAuthenticated || !user) return null;

	return (
		<div ref={ref} className={cx("kavach-user-button relative", classNames?.root ?? className)}>
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				className={cx(
					"kavach-user-trigger flex items-center gap-2 rounded-full p-1 transition-colors hover:bg-zinc-100 dark:hover:bg-zinc-800",
					classNames?.trigger,
				)}
				aria-expanded={open}
				aria-haspopup="menu"
			>
				<Avatar src={user.image} name={user.name} className={cx("", classNames?.avatar)} />
			</button>

			{open && (
				<div
					role="menu"
					className={cx(
						"kavach-user-dropdown absolute right-0 top-full z-50 mt-2 w-56 overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-lg dark:border-zinc-700 dark:bg-zinc-900",
						classNames?.dropdown,
					)}
				>
					{/* User info header */}
					<div className="border-b border-zinc-100 px-4 py-3 dark:border-zinc-800">
						{user.name && (
							<p
								className={cx(
									"kavach-user-name truncate text-sm font-medium text-zinc-900 dark:text-zinc-100",
									classNames?.name,
								)}
							>
								{user.name}
							</p>
						)}
						{showEmail && user.email && (
							<p
								className={cx(
									"kavach-user-email truncate text-xs text-zinc-500 dark:text-zinc-400",
									classNames?.email,
								)}
							>
								{user.email}
							</p>
						)}
					</div>

					{/* Custom menu items */}
					{menuItems.length > 0 && (
						<div className="border-b border-zinc-100 py-1 dark:border-zinc-800">
							{menuItems.map((item) => (
								<button
									key={item.label}
									type="button"
									role="menuitem"
									onClick={() => {
										setOpen(false);
										item.onClick();
									}}
									className={cx(
										`kavach-menu-item flex w-full items-center gap-2 px-4 py-2 text-left text-sm transition-colors hover:bg-zinc-50 dark:hover:bg-zinc-800 ${
											item.danger
												? "text-red-600 dark:text-red-400"
												: "text-zinc-700 dark:text-zinc-300"
										}`,
										classNames?.menuItem,
									)}
								>
									{item.icon && (
										<span className="flex h-4 w-4 items-center justify-center">{item.icon}</span>
									)}
									{item.label}
								</button>
							))}
						</div>
					)}

					{/* Sign out */}
					<div className="py-1">
						<button
							type="button"
							role="menuitem"
							onClick={handleSignOut}
							className={cx(
								"kavach-menu-item flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-zinc-700 transition-colors hover:bg-zinc-50 dark:text-zinc-300 dark:hover:bg-zinc-800",
								classNames?.menuItem,
							)}
						>
							<svg
								className="h-4 w-4"
								fill="none"
								viewBox="0 0 24 24"
								strokeWidth="1.5"
								stroke="currentColor"
								aria-hidden="true"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9"
								/>
							</svg>
							Sign out
						</button>
					</div>
				</div>
			)}
		</div>
	);
}
