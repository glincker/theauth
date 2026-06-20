import { useSignUp } from "@theauth/react";
import type { FormEvent, ReactNode } from "react";
import { useCallback, useState } from "react";
import type {
	ButtonSlotProps,
	DividerSlotProps,
	ErrorSlotProps,
	InputSlotProps,
	LinkSlotProps,
	SignUpProps,
} from "../types.js";
import { cx } from "../utils.js";
import { AuthCard } from "./auth-card.js";
import { OAuthButtons } from "./oauth-buttons.js";

// ─── Default slots ───────────────────────────────────────────────────────────

function DefaultInput({ label, error, ...rest }: InputSlotProps): ReactNode {
	return (
		<label className="kavach-field flex flex-col gap-1.5">
			<span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
			<input
				{...rest}
				className={
					rest.className ??
					"kavach-input w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition-colors placeholder:text-zinc-400 focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
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
				"kavach-btn w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
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

function DefaultDivider({ label, className }: DividerSlotProps): ReactNode {
	return (
		<div className={className ?? "kavach-divider flex items-center gap-3 py-1"}>
			<div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
			{label && <span className="text-xs text-zinc-400">{label}</span>}
			<div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
		</div>
	);
}

function DefaultError({ message, className }: ErrorSlotProps): ReactNode {
	return (
		<div
			className={
				className ??
				"kavach-error rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
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
				"kavach-link text-sm font-medium text-zinc-900 hover:underline dark:text-zinc-100"
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

export function SignUp({
	classNames,
	components,
	providers = [],
	basePath = "/api/kavach",
	onSuccess,
	signInUrl,
	onSignIn,
	showName = true,
	confirmPassword = true,
	title = "Create account",
	footer,
	disabled,
	className,
}: SignUpProps): ReactNode {
	const { signUp, isLoading, error } = useSignUp();
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [passwordConfirm, setPasswordConfirm] = useState("");
	const [localError, setLocalError] = useState<string | null>(null);

	const Input = components?.Input ?? DefaultInput;
	const Btn = components?.Button ?? DefaultButton;
	const Divider = components?.Divider ?? DefaultDivider;
	const Err = components?.Error ?? DefaultError;
	const Link = components?.Link ?? DefaultLink;

	const handleSubmit = useCallback(
		async (e: FormEvent) => {
			e.preventDefault();
			setLocalError(null);

			if (confirmPassword && password !== passwordConfirm) {
				setLocalError("Passwords don't match");
				return;
			}

			if (password.length < 8) {
				setLocalError("Password must be at least 8 characters");
				return;
			}

			const result = await signUp(email, password, showName ? name || undefined : undefined);
			if (result.success) {
				onSuccess?.();
			}
		},
		[email, password, passwordConfirm, name, signUp, onSuccess, confirmPassword, showName],
	);

	const displayError = localError ?? error;

	return (
		<AuthCard
			classNames={{
				root: classNames?.root ?? className,
				card: classNames?.card,
				title: classNames?.title,
			}}
			title={title}
			description="Enter your details to get started"
		>
			<div className="flex flex-col gap-4">
				{/* OAuth providers */}
				{providers.length > 0 && (
					<>
						<div className={cx("kavach-oauth-section", classNames?.oauthSection)}>
							<OAuthButtons
								providers={providers}
								basePath={basePath}
								mode="signup"
								layout={providers.length > 3 ? "grid" : "list"}
								disabled={disabled}
								components={components ? { Button: components.Button } : undefined}
							/>
						</div>
						<Divider label="or" />
					</>
				)}

				<form onSubmit={handleSubmit} className={cx("flex flex-col gap-4", classNames?.form)}>
					{displayError && <Err message={displayError} />}

					{showName && (
						<Input
							label="Name"
							type="text"
							name="name"
							placeholder="Your name"
							value={name}
							onChange={(e) => setName(e.target.value)}
							autoComplete="name"
							disabled={disabled ?? isLoading}
						/>
					)}

					<Input
						label="Email"
						type="email"
						name="email"
						placeholder="you@example.com"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						required
						autoComplete="email"
						disabled={disabled ?? isLoading}
					/>

					<Input
						label="Password"
						type="password"
						name="password"
						placeholder="At least 8 characters"
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						required
						minLength={8}
						autoComplete="new-password"
						disabled={disabled ?? isLoading}
					/>

					{confirmPassword && (
						<Input
							label="Confirm password"
							type="password"
							name="password-confirm"
							placeholder="Repeat your password"
							value={passwordConfirm}
							onChange={(e) => setPasswordConfirm(e.target.value)}
							required
							autoComplete="new-password"
							disabled={disabled ?? isLoading}
						/>
					)}

					<Btn type="submit" loading={isLoading} disabled={disabled}>
						Create account
					</Btn>
				</form>

				{/* Footer: sign in link */}
				{(signInUrl ?? onSignIn) && (
					<p
						className={cx(
							"kavach-footer text-center text-sm text-zinc-500 dark:text-zinc-400",
							classNames?.footer,
						)}
					>
						Already have an account?{" "}
						<Link href={signInUrl ?? "#"} onClick={onSignIn}>
							Sign in
						</Link>
					</p>
				)}

				{footer}
			</div>
		</AuthCard>
	);
}
