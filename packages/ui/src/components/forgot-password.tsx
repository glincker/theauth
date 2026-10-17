import type { FormEvent, ReactNode } from "react";
import { useCallback, useState } from "react";
import type { ForgotPasswordProps, LinkSlotProps } from "../types.js";
import { cx } from "../utils.js";
import { AuthCard } from "./auth-card.js";
import { DefaultButton, DefaultError, DefaultInput } from "./defaults.js";

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
