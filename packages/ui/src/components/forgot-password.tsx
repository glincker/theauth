import type { FormEvent, ReactNode } from "react";
import { useCallback, useState } from "react";
import type {
	ButtonSlotProps,
	ErrorSlotProps,
	ForgotPasswordProps,
	InputSlotProps,
	LinkSlotProps,
} from "../types.js";
import { cx } from "../utils.js";
import { AuthCard } from "./auth-card.js";

// ─── Default slots ───────────────────────────────────────────────────────────

function DefaultInput({ label, error, ...rest }: InputSlotProps): ReactNode {
	return (
		<label className="theauth-field flex flex-col gap-1.5">
			<span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
			<input
				{...rest}
				className={
					rest.className ??
					"theauth-input w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition-colors placeholder:text-zinc-400 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
				}
			/>
			{error && <p className="text-xs text-red-500">{error}</p>}
		</label>
	);
}

function DefaultButton({ loading, children, ...rest }: ButtonSlotProps): ReactNode {
	return (
		<button
			{...rest}
			disabled={rest.disabled ?? loading}
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

function DefaultError({ message, className }: ErrorSlotProps): ReactNode {
	return (
		<div
			className={
				className ??
				"theauth-error rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
			}
		>
			{message}
		</div>
	);
}

function DefaultLink({ href, children, className, onClick }: LinkSlotProps): ReactNode {
	return (
		<a
			href={href}
			onClick={
				onClick
					? (e: React.MouseEvent) => {
							e.preventDefault();
							onClick();
						}
					: undefined
			}
			className={
				className ??
				"theauth-link text-sm font-medium text-zinc-900 hover:underline dark:text-zinc-100"
			}
		>
			{children}
		</a>
	);
}

function Spinner(): ReactNode {
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

// ─── Component ───────────────────────────────────────────────────────────────

export function ForgotPassword({
	classNames,
	components,
	basePath = "/api/theauth",
	onSuccess,
	signInUrl,
	onSignIn,
	title = "Reset password",
	className,
}: ForgotPasswordProps): ReactNode {
	const [email, setEmail] = useState("");
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [sent, setSent] = useState(false);

	const base = basePath.replace(/\/$/, "");

	const Input = components?.Input ?? DefaultInput;
	const Btn = components?.Button ?? DefaultButton;
	const Err = components?.Error ?? DefaultError;
	const Link = components?.Link ?? DefaultLink;

	const handleSubmit = useCallback(
		async (e: FormEvent) => {
			e.preventDefault();
			if (!email) return;
			setIsLoading(true);
			setError(null);
			try {
				await fetch(`${base}/auth/forgot-password`, {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email }),
				});
				// Always show success to prevent email enumeration
				setSent(true);
				onSuccess?.();
			} catch {
				setError("Network error. Please try again.");
			} finally {
				setIsLoading(false);
			}
		},
		[email, base, onSuccess],
	);

	return (
		<AuthCard
			classNames={{
				root: classNames?.root ?? className,
				card: classNames?.card,
				title: classNames?.title,
			}}
			title={title}
			description={sent ? undefined : "We'll send you a link to reset your password"}
		>
			<div className="flex flex-col gap-4">
				{sent ? (
					<div
						className={cx(
							"theauth-success rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-center text-sm text-green-700 dark:border-green-800 dark:bg-green-900/20 dark:text-green-400",
							classNames?.success,
						)}
					>
						<p className="font-medium">Check your email</p>
						<p className="mt-1 text-xs opacity-80">
							If an account exists for {email}, we sent a password reset link.
						</p>
						<button
							type="button"
							onClick={() => setSent(false)}
							className="mt-2 text-xs underline opacity-60 hover:opacity-100"
						>
							Try again
						</button>
					</div>
				) : (
					<form onSubmit={handleSubmit} className={cx("flex flex-col gap-4", classNames?.form)}>
						{error && <Err message={error} />}

						<Input
							label="Email"
							type="email"
							name="email"
							placeholder="you@example.com"
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							required
							autoComplete="email"
							disabled={isLoading}
						/>

						<Btn type="submit" loading={isLoading}>
							Send reset link
						</Btn>
					</form>
				)}

				{(signInUrl ?? onSignIn) && (
					<p className="text-center text-sm text-zinc-500 dark:text-zinc-400">
						Remember your password?{" "}
						<Link href={signInUrl ?? "#"} onClick={onSignIn}>
							Sign in
						</Link>
					</p>
				)}
			</div>
		</AuthCard>
	);
}
